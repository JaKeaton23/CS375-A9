#include <bits/stdc++.h>
using namespace std;


enum class Protection { READ_ONLY, READ_WRITE };
enum class Access { READ, WRITE };
enum class Policy { FIFO, LRU };

struct CLI {
    int frames = 16;
    int page_size = 1000;
    int segments = 3;
    int dir_size = 4;                 // entries per directory; square layout
    Policy policy = Policy::FIFO;
    unsigned seed = (unsigned)time(nullptr);
    bool stress = false;
    bool batch = false;
    string batch_file = "addrs.txt";
    int stress_n = 100;
    double stress_valid_ratio = 0.7;
} cli;

// ---------- Types ----------
struct Page {
    int frame = -1;                   // -1 => not mapped
    bool present = false;
    Protection prot = Protection::READ_WRITE;
    int last_access = 0;              // for LRU
};

struct Segment {
    int base = 0;                     // physical base
    int limit_pages = 0;              // logical pages in this segment
    Protection prot = Protection::READ_WRITE;
};

struct FrameMeta {
    bool free = true;
    int seg = -1, dir = -1, page = -1;
    int loaded_time = 0;
    int last_access = 0;
};

// ---------- Physical Memory ----------
class PhysicalMemory {
public:
    explicit PhysicalMemory(int n, Policy p) : num_frames(n), policy(p) {
        meta.resize(num_frames);
    }

    int allocate_any_free() {         // grab first free frame if possible
        for (int i = 0; i < num_frames; ++i)
            if (meta[i].free) { meta[i].free = false; fifo_q.push(i); return i; }
        return -1;
    }

    // choose victim under current policy
    int choose_victim(int now) {
        if (policy == Policy::FIFO) {
            while (!fifo_q.empty() && meta[fifo_q.front()].free) fifo_q.pop();
            if (fifo_q.empty()) return -1;
            int f = fifo_q.front(); fifo_q.pop(); fifo_q.push(f);
            return f;
        } else { // LRU
            int best = -1, ts = INT_MAX;
            for (int i = 0; i < num_frames; ++i)
                if (!meta[i].free && meta[i].last_access < ts) { ts = meta[i].last_access; best = i; }
            return best;
        }
    }

    void map(int frame, int seg, int dir, int page, int now) {
        meta[frame].free = false;
        meta[frame].seg = seg; meta[frame].dir = dir; meta[frame].page = page;
        meta[frame].loaded_time = now; meta[frame].last_access = now;
        fifo_q.push(frame); // harmless for LRU
    }

    void touch(int frame, int now) { if (valid(frame)) meta[frame].last_access = now; }
    void free_frame(int frame)      { if (frame >= 0 && frame < num_frames) meta[frame] = FrameMeta{}; }

    double utilization() const {
        int used = 0; for (auto &m : meta) used += !m.free;
        return (double)used / (double)num_frames * 100.0;
    }

    const FrameMeta& info(int frame) const { return meta[frame]; }
    int frames() const { return num_frames; }

private:
    bool valid(int f){ return f>=0 && f<num_frames && !meta[f].free; }
    int num_frames; Policy policy;
    vector<FrameMeta> meta; queue<int> fifo_q;
};

// ---------- Page Tables ----------
class PageTable {
public:
    PageTable() = default;
    PageTable(int pages, int page_size) : pages_(pages), page_size_(page_size) {
        table_.assign(pages_, Page{});
        randomize_presence();         // some pages start absent to force faults
    }
    Page& at(int i) { return table_[i]; }
    const Page& at(int i) const { return table_[i]; }
    int size() const { return pages_; }
    int pageSize() const { return page_size_; }

private:
    void randomize_presence() {
        for (auto &p : table_) {
            p.present = rand()%2;
            p.frame = -1;
            p.prot = (rand()%2)?Protection::READ_ONLY:Protection::READ_WRITE;
        }
    }
    int pages_ = 0, page_size_ = 0;
    vector<Page> table_;
};

struct DirEntry {                      // second level allocates on first use
    bool present = false;
    unique_ptr<PageTable> pt = nullptr;
};

// ---------- Segment Table + Translation ----------
struct Metrics {
    long translations = 0, faults = 0, replacements = 0, prot_viol = 0;
    long seg_faults = 0, offset_faults = 0, writes_denied = 0, logs = 0;
    long total_latency = 0;
};

class SegmentTable {
public:
    SegmentTable(int segs, int dir_size, int page_size, PhysicalMemory &pm)
        : dir_size_(dir_size), page_size_(page_size), pm_(pm) {
        segments_.resize(segs);
        dirs_.resize(segs);
        for (int s = 0; s < segs; ++s) {
            segments_[s].base = 1000 + s*5000;
            segments_[s].limit_pages = 3 + rand()%5;         // 3..7 pages
            segments_[s].prot = (rand()%2)?Protection::READ_ONLY:Protection::READ_WRITE;
            dirs_[s] = std::vector<DirEntry>(dir_size_);
        }
    }

    // two-level index split; returns physical address or -1
    long translate(int seg, int pageNum, int offset, Access acc, int &latency, ofstream* elog=nullptr) {
        int now = ++time_;
        latency = 1 + rand()%5;                              // tiny simulated delay

        // segment checks
        if (seg < 0 || seg >= (int)segments_.size()) { metrics_.seg_faults++; log(elog,"Segmentation Fault: bad segment"); return -1; }
        const Segment &S = segments_[seg];
        if (acc == Access::WRITE && S.prot == Protection::READ_ONLY) { metrics_.prot_viol++; metrics_.writes_denied++; log(elog,"Write to RO segment"); return -1; }
        if (pageNum < 0 || pageNum >= S.limit_pages) { metrics_.seg_faults++; log(elog,"Page exceeds seg limit"); return -1; }
        if (offset < 0 || offset >= page_size_) { metrics_.offset_faults++; log(elog,"Offset out of range"); return -1; }

        // two-level split
        int entriesPerPT = dir_size_;
        int dir = pageNum / entriesPerPT;
        int page = pageNum % entriesPerPT;

        // lazy alloc of second level
        DirEntry &de = dirs_[seg][dir];
        if (!de.present) { de.present = true; de.pt = make_unique<PageTable>(entriesPerPT, page_size_); }
        Page &P = de.pt->at(page);

        // page-level protection
        if (acc == Access::WRITE && P.prot == Protection::READ_ONLY) { metrics_.prot_viol++; metrics_.writes_denied++; log(elog,"Write to RO page"); return -1; }

        // handle absence: free -> victim -> map
        if (!P.present) {
            metrics_.faults++;
            int f = pm_.allocate_any_free();
            if (f == -1) {
                int victim = pm_.choose_victim(now);
                if (victim == -1) { log(elog,"No victim available"); return -1; }
                FrameMeta finfo = pm_.info(victim);
                if (owning_clear(finfo)) { pm_.free_frame(victim); metrics_.replacements++; }
                f = victim;
            }
            P.present = true; P.frame = f; P.last_access = now;
            pm_.map(f, seg, dir, page, now);
        } else {
            pm_.touch(P.frame, now); P.last_access = now;
        }

        long physical = segments_[seg].base + (long)pageNum * page_size_ + offset;
        metrics_.translations++; metrics_.total_latency += latency;
        return physical;
    }

    void printMemoryMap(ostream& os) const {
        os << "===== Memory Map =====\n";
        os << "Segments=" << segments_.size() << " Dir=" << dir_size_ << " PageSize=" << page_size_ << "\n";
        for (size_t s = 0; s < segments_.size(); ++s) {
            const Segment &S = segments_[s];
            os << "Seg " << s << " Base=" << S.base << " Limit=" << S.limit_pages
               << " Prot=" << (S.prot==Protection::READ_ONLY?"RO":"RW") << "\n";
            for (int d = 0; d < dir_size_; ++d) {
                const DirEntry &de = dirs_[s][d];
                os << "  Dir " << d << " present=" << (de.present?"Y":"N") << "\n";
                if (de.present && de.pt) {
                    for (int p = 0; p < de.pt->size(); ++p) {
                        const Page &Pg = de.pt->at(p);
                        os << "    Page " << p
                           << " present=" << (Pg.present?"Y":"N")
                           << " frame=" << Pg.frame
                           << " prot=" << (Pg.prot==Protection::READ_ONLY?"RO":"RW") << "\n";
                    }
                }
            }
        }
        os << "======================\n";
    }

    const Metrics& metrics() const { return metrics_; }
    int pageSize() const { return page_size_; }

private:
    bool owning_clear(const FrameMeta &m) {                 // unlink victim owner
        if (m.seg < 0) return false;
        if (m.seg >= (int)dirs_.size()) return false;
        if (m.dir < 0 || m.dir >= (int)dirs_[m.seg].size()) return false;
        DirEntry &de = dirs_[m.seg][m.dir];
        if (!de.present || !de.pt) return false;
        if (m.page < 0 || m.page >= de.pt->size()) return false;
        Page &P = de.pt->at(m.page);
        P.present = false; P.frame = -1;
        return true;
    }

    void log(ofstream* f, const string& s){ if (f && *f) (*f)<<s<<"\n"; metrics_.logs++; }

    int dir_size_, page_size_;
    PhysicalMemory &pm_;
    vector<Segment> segments_;
    vector<vector<DirEntry>> dirs_;
    Metrics metrics_;
    int time_ = 0;
};

// ---------- Helpers ----------
static Policy parsePolicy(string s){ for(char &c:s) c=tolower(c); return s=="lru"?Policy::LRU:Policy::FIFO; }
static void usage(const char* p){
    cerr<<"Usage: "<<p<<" [--frames N] [--page-size N] [--segments N] [--dir-size N]"
          " [--policy fifo|lru] [--seed N] [--stress N [--valid x]] [--batch file]\n";
}

// ---------- Main ----------
int main(int argc, char** argv) {
    // CLI (simple and explicit)
    for (int i=1;i<argc;++i){
        string a=argv[i]; auto need=[&](int j){ if(j+1>=argc){ usage(argv[0]); exit(1);} };
        if(a=="--frames"){ need(i); cli.frames=stoi(argv[++i]); }
        else if(a=="--page-size"){ need(i); cli.page_size=stoi(argv[++i]); }
        else if(a=="--segments"){ need(i); cli.segments=stoi(argv[++i]); }
        else if(a=="--dir-size"){ need(i); cli.dir_size=stoi(argv[++i]); }
        else if(a=="--policy"){ need(i); cli.policy=parsePolicy(argv[++i]); }
        else if(a=="--seed"){ need(i); cli.seed=(unsigned)stoul(argv[++i]); }
        else if(a=="--stress"){ need(i); cli.stress=true; cli.stress_n=stoi(argv[++i]); }
        else if(a=="--valid"){ need(i); cli.stress_valid_ratio=stod(argv[++i]); }
        else if(a=="--batch"){ need(i); cli.batch=true; cli.batch_file=argv[++i]; }
        else { usage(argv[0]); return 1; }
    }
    srand(cli.seed);

    ofstream elog("results.txt");
    if(!elog) cerr<<"Warning: couldn't open results.txt\n";

    PhysicalMemory pm(cli.frames, cli.policy);
    SegmentTable ST(cli.segments, cli.dir_size, cli.page_size, pm);

    cout<<"=== Advanced Segmented, Paged Memory Simulator ===\n";
    cout<<"Frames="<<cli.frames<<" PageSize="<<cli.page_size<<" Segments="<<cli.segments
        <<" DirSize="<<cli.dir_size<<" Policy="<<(cli.policy==Policy::FIFO?"FIFO":"LRU")
        <<" Seed="<<cli.seed<<"\n\n";

    ST.printMemoryMap(cout);
    cout<<fixed<<setprecision(2);

    auto show = [&](){               // quick metrics dump
        const auto&m=ST.metrics();
        cout<<"\n--- Metrics ---\n";
        cout<<"Translations: "<<m.translations<<"\n";
        cout<<"Page Faults:  "<<m.faults<<"\n";
        cout<<"Replacements: "<<m.replacements<<"\n";
        cout<<"Prot Viol:    "<<m.prot_viol<<" (writes denied "<<m.writes_denied<<")\n";
        cout<<"Seg Faults:   "<<m.seg_faults<<"  Offset Faults: "<<m.offset_faults<<"\n";
        cout<<"Utilization:  "<<pm.utilization()<<"%\n";
        cout<<"Avg Latency:  "<<(m.translations? (double)m.total_latency/m.translations:0.0)<<"\n";
        cout<<"--------------\n";
    };

    // batch mode: file with lines "seg page offset access(0/1)"
    if (cli.batch){
        ifstream in(cli.batch_file);
        if(!in){ cerr<<"Batch file not found: "<<cli.batch_file<<"\n"; return 1; }
        cout<<"Batch: "<<cli.batch_file<<"\n";
        int seg, page, off, acc;
        while(in>>seg>>page>>off>>acc){
            int lat=0;
            long pa=ST.translate(seg,page,off,acc?Access::WRITE:Access::READ,lat,&elog);
            if(pa!=-1) cout<<"OK  -> Phys="<<pa<<"  Lat="<<lat<<"\n";
            else       cout<<"FAIL ("<<seg<<","<<page<<","<<off<<","<<(acc?"W":"R")<<")\n";
        }
        show(); ST.printMemoryMap(cout);
        cout<<"\n(Logged to results.txt)\n"; return 0;
    }

    // stress mode: randomized addresses with a valid/invalid mix
    if (cli.stress){
        cout<<"Stress: N="<<cli.stress_n<<" valid="<<cli.stress_valid_ratio<<"\n";
        std::mt19937 rng(cli.seed); std::uniform_real_distribution<> U(0.0,1.0);
        for(int i=0;i<cli.stress_n;++i){
            int seg=rng()%cli.segments;
            bool valid=U(rng)<cli.stress_valid_ratio;
            int page = valid ? rng()%max(1, ST.pageSize()) : (rng()%20 + 20);
            int off  = valid ? rng()%cli.page_size        : (cli.page_size + rng()%500);
            Access a = (rng()%2)?Access::READ:Access::WRITE;
            int lat=0; (void)ST.translate(seg,page,off,a,lat,&elog);
        }
        show(); ST.printMemoryMap(cout);
        cout<<"\n(Logged to results.txt)\n"; return 0;
    }

    // interactive: quick manual testing
    cout<<"Interactive. Enter: seg page offset access(0=R,1=W), or -1 to quit.\n";
    while(true){
        cout<<"> ";
        int seg; if(!(cin>>seg)) break; if(seg==-1) break;
        int page,off,acc; cin>>page>>off>>acc;
        int lat=0;
        long pa=ST.translate(seg,page,off,acc?Access::WRITE:Access::READ,lat,&elog);
        if(pa!=-1) cout<<"Physical: "<<pa<<" | Latency: "<<lat<<"\n";
        else       cout<<"Error. See results.txt.\n";
    }

    show(); ST.printMemoryMap(cout);
    cout<<"\nDone.\n";
    return 0;
}

