#include "../src/signatures.hpp"
#include "../src/pe.hpp"
#include <fstream>
#include <iostream>

using namespace argus;
static std::vector<uint8_t> slurp(const std::string& p){
    std::ifstream f(p,std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
}
int failures=0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

static void report(const std::string& tag, const sig::ScoreResult& r){
    std::cout<<"\n["<<tag<<"] score="<<r.score<<"  verdict="<<sig::verdict_name(r.verdict)<<"\n";
    for(auto& h: r.capabilities){
        std::cout<<"   + "<<sig::meta(h.cap).label<<" :";
        for(size_t i=0;i<h.apis.size() && i<4;++i) std::cout<<" "<<h.apis[i];
        std::cout<<"\n";
    }
    for(auto& f: r.findings) std::cout<<"   ! "<<f.text<<"\n";
}

int main(){
    // 1. Real benign launcher stubs -> should be CLEAN/LOW, no scary findings
    for(auto p : {"test/sample64.exe","test/sample32.exe"}){
        pe::Analyzer a(slurp(p));
        auto info=a.analyze();
        auto r=sig::score(info);
        report(p, r);
        CHECK(r.verdict==sig::Verdict::Clean || r.verdict==sig::Verdict::Low);
    }

    // 2. Synthetic injector: build a fake Info with classic injection imports
    {
        pe::Info inj;
        inj.valid=true; inj.total_imports=6;
        pe::Import k; k.dll="kernel32.dll";
        k.functions={"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","OpenProcess"};
        pe::Import n; n.dll="ntdll.dll"; n.functions={"LoadLibraryA","GetProcAddress"};
        inj.imports={k,n};
        // a packed-looking RWX section
        pe::Section s; s.name=".text"; s.raw_size=4096; s.entropy=7.6;
        s.executable=true; s.writable=true; s.readable=true; s.virtual_addr=0x1000;
        inj.entry_point_rva=0x1000;
        inj.sections={s};
        auto r=sig::score(inj);
        report("synthetic-injector", r);
        CHECK(r.verdict==sig::Verdict::Malicious);
        // must have flagged injection + the injection+dynamic combo + RWX + entropy
        bool has_inj=false; for(auto&h:r.capabilities) if(h.cap==sig::Capability::ProcessInjection) has_inj=true;
        CHECK(has_inj);
    }

    // 3. Synthetic keylogger: input capture + networking
    {
        pe::Info kl; kl.valid=true; kl.total_imports=10;
        pe::Import u; u.dll="user32.dll"; u.functions={"GetAsyncKeyState","GetForegroundWindow","SetWindowsHookExA"};
        pe::Import w; w.dll="ws2_32.dll"; w.functions={"socket","connect","send"};
        kl.imports={u,w};
        pe::Section s; s.name=".text"; s.raw_size=8192; s.entropy=6.0;
        s.executable=true; s.readable=true; s.virtual_addr=0x1000; kl.entry_point_rva=0x1000;
        kl.sections={s};
        auto r=sig::score(kl);
        report("synthetic-keylogger", r);
        CHECK(r.score>=30);  // suspicious or worse
    }

    std::cout<<"\n"<<(failures? std::to_string(failures)+" SCORING test(s) failed":"ALL SCORING TESTS PASSED")<<"\n";
    return failures;
}
