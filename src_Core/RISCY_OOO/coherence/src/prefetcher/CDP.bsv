import MemoryTypes::*; // Import from RISCYOOO
import TlbTypes ::*;
import CCTypes ::*;
import FIFO::*;
import Fifos::*;
import Ehr::*;
import Vector::*;
import ConfigReg::*;

import Types::*;
import RWBramCore::*;
import Prefetcher_intf::*;

typedef struct {
    reqT req;
    Line line;
} L1ToCDPT#(type reqT) deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
} NextCandT deriving (Bits, FShow, Eq);

module mkCDP(
    CacheLinePrefetcher#(reqT)
) provisos (
    Bits#(reqT, _reqSz), 
    FShow#(reqT),
    IsProcRq#(reqT)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 8 used, one line there is potentially 8 candidate vaddr, size 8 for each FIFO
    SupFifo#(8, 8, NextCandT) nextCandidateBuffer <- mkSupFifo;

    rule deqLineL1;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req)); // This is purely for $display
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP deqLineL1", $time);
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin
                nextCandidateBuffer.enqS[enqIdx].enq(
                    NextCandT{
                        paddr: getReqAddr(x.req), 
                        vaddr: x.line[i]});
                // Probably change logging here to just see the candidate vaddr -> candidate paddr?
                $display("%t AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", $time, i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
                enqIdx = enqIdx + 1;
            end
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP reportIncomingCacheLine", $time);
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        if (hitMiss == HIT) begin
            $display("%t AlexLog: prefetcher report HIT %h", $time, addr);
        end
        else begin
            $display("%t AlexLog: prefetcher report MISS %h", $time, addr);
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr; // Do I want some condition here?
        // Found a virtual address and need to translate it now,
        // because I'm matching the VPN that caused to load to potential vaddrs with the same VPN, then the PPN should also be the same
        let x = nextCandidateBuffer.deqS[0].first;
        nextCandidateBuffer.deqS[0].deq;
        // Use the same VPN -> PPN, but get the offset of the candidate vaddr
        Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
        $display("%t AlexLog: CDP Prefetch addr issued. paddr: %h | vaddr: %h", $time, nextAddr, x.vaddr);
        return PendingPrefetch {
            addr: nextAddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule

typedef struct {
    Bit#(16)       pcHash;
    LineDataOffset lineOffset;
} TrainingTableEntryT deriving (Bits, FShow, Eq);

typedef struct {
    reqT req;
    idxT ttIdx;
    Bool missedOnThisVaddr;
    LineDataOffset offset;
} TrainingTableRespQT#(type reqT, type idxT) deriving (Bits, FShow, Eq);

// PC-offset confidence table entry: one 3-bit confidence counter per cache line offset (8 offsets)
typedef Vector#(8, Bit#(3)) PCOffsetConfT;

module mkCDPStateful#(
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT),

    NumAlias#(trainingTableIdxBits, TLog#(trainingTableSize)),
    Alias#(trainingTableIdxT, Bit#(trainingTableIdxBits)),

    NumAlias#(pcTableIdxBits, TLog#(pcTableSize)),
    Alias#(pcTableIdxT, Bit#(pcTableIdxBits)),
    Alias#(ttRespQT, TrainingTableRespQT#(reqT, trainingTableIdxT)),

    Add#(a__, TLog#(trainingTableSize), 64)

);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 8 used, one line there is potentially 8 candidate vaddr, size 8 for each FIFO
    //SupFifo#(8, 8, NextCandT) nextCandidateBuffer <- mkSupFifo;

    RWBramCore#(trainingTableIdxT, Maybe#(TrainingTableEntryT)) trainingTable <- mkRWBramCoreForwarded(); // Training table should be indexed by vaddr and value should contain the PC and offset within the line at that miss
    SupFifo#(8, 8, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(8, 8, trainingTableIdxT) ttRdReqSupFIFO <- mkSupFifo;

    // PC-offset confidence table: indexed by truncated pcHash, stores 4-bit confidence per offset
    RWBramCore#(pcTableIdxT, Maybe#(PCOffsetConfT)) pcTable <- mkRWBramCoreForwarded();

    FIFO#(NextCandT) nextCandidateBuffer <- mkFIFO;


    // Init registers
    Reg#(Bool) trainingTableInited <- mkConfigReg(False);
    Reg#(Bit#(trainingTableIdxBits)) trainingTableInitCount <- mkReg(0);
    Reg#(Bool) pcTableInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcTableInitCount <- mkReg(0);

    // Whether we have inited
    function Bool inited;
        //return ptrTableInited && trainingTableInited && tlbReqFreeQInited;
        return trainingTableInited && pcTableInited;
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!trainingTableInited);
        trainingTable.wrReq(trainingTableInitCount, Invalid);
        if (trainingTableInitCount == ~0) begin
            trainingTableInited <= True;
            // Also seed the Lfsr here
            //trainingDecayLfsr.seed('h11);
            $display("%t AlexLog: Training table inited", $time);
        end
        trainingTableInitCount <= trainingTableInitCount + 1;
    endrule

    (* mutually_exclusive = "doPcTableInit, processTtRdReq, ttAccess" *)
    rule doPcTableInit(!pcTableInited);
        pcTable.wrReq(pcTableInitCount, Invalid);
        if (pcTableInitCount == ~0) begin
            pcTableInited <= True;
            $display("%t AlexLog: PC table inited", $time);
        end
        pcTableInitCount <= pcTableInitCount + 1;
    endrule
    
    (* descending_urgency = "deqCacheLines, processTtRdReq, ttAccess" *)
    rule deqCacheLines; // Dequeue the incoming cache lines
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req)); // Use this and index into the training table to see if it has been seen before, if so CRUD PC table entry
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP deqCacheLines", $time);
        // We want to fill the training table with potential vaddrs if the vaddr hasn't been seen before
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin // If it looks like a vaddr (in the same page)
                // Index the training table by a hash of the candidate vaddr (skip cache line offset bits) AlexNote: Not sure if this is correct?
                trainingTableIdxT idx = truncate(x.line[i] >> valueOf(LgLineSzBytes));
                Bool missedOnThisVaddr = (dataSel == fromInteger(i));
                if (missedOnThisVaddr)
                    $display("%t AlexLog: found a candidate vaddr that missed", $time);
                ttRespQ.enqS[enqIdx].enq(
                    TrainingTableRespQT{
                        req: x.req, 
                        ttIdx: idx, 
                        missedOnThisVaddr: missedOnThisVaddr,
                        offset: fromInteger(i)});
                ttRdReqSupFIFO.enqS[enqIdx].enq(idx); // Since this can call multiple times per cycle, need to send it to a SupFIFO
                $display("%t AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", $time, i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
                enqIdx = enqIdx + 1;
            end
        end
    endrule

    rule processTtRdReq(inited);
        let idx = ttRdReqSupFIFO.deqS[0].first;
        ttRdReqSupFIFO.deqS[0].deq;
        trainingTable.rdReq(idx); // Sequeuntially queue the index
    endrule

    rule ttAccess(inited);
        let x = trainingTable.rdResp;
        trainingTable.deqRdResp;
        ttRespQT respQ = ttRespQ.deqS[0].first;
        ttRespQ.deqS[0].deq;
        // This if statement also needs to check if the BRAM table has been init with some values
        //if (trainingTable.rdRespValid && respQ.missedOnThisVaddr) begin // Vaddr already exists in the training table and the cache miss is for that specific vaddr
        if (x matches tagged Valid .ttRdResp) begin // Vaddr already exists in the training table and the cache miss is for that specific vaddr
            if (respQ.missedOnThisVaddr) begin
                $display("%t AlexLog: PC table needs update", $time);
                let pctIdx = truncate(getPcHash(respQ.req) >> valueof());
                pct.wrReq();
            end
            // If the vaddr trainingTable entry already exists then no need to update
        end else begin // vaddr doesn't exist, create entry
            trainingTable.wrReq(respQ.ttIdx, Valid(TrainingTableEntryT {
                pcHash:     getPcHash(respQ.req),
                lineOffset: respQ.offset // Offset of where this vaddr in the line was found
            }));
            $display("%t AlexLog: Wrote to training table, idx: %d", $time, respQ.ttIdx);
        end
    endrule

    //rule thing;
        // For that specific cache line fill -> the actual data being pulled needs to be checked if it is a candidate vaddr
        // If so the go into the training table -> if seen before -> update confidence on PC-offset table

        // For each candidate vaddr in cache line fill
        // If it doesn't exist in the training table create an entry
        // else it already exists AND it is the datasel (the actual data word requested in the miss) then update confidence
        // Impl:
            // Send off a read request to the training table
            // Read the responses, if it exists then check if the datasel thing we passed through in the side pipe is true
            // If it doesn't exist the send a write request to the training table

        // When we see a reportAccess to a specific PC, check the PC table and see if any offset has good confidence. Prefetch if so
    //endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP reportIncomingCacheLine", $time);
    endmethod

    // Here we want to see that on access
    // On access to a PC we have in the PC table, if confidence is good then issue prefetch
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        if (hitMiss == HIT) begin
            $display("%t AlexLog: prefetcher report HIT %h", $time, addr);
        end
        else begin
            $display("%t AlexLog: prefetcher report MISS %h", $time, addr);
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr; // Do I want some condition here?
        // Found a virtual address and need to translate it now,
        // because I'm matching the VPN that caused to load to potential vaddrs with the same VPN, then the PPN should also be the same
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        // Use the same VPN -> PPN, but get the offset of the candidate vaddr
        Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
        $display("%t AlexLog: CDP Prefetch addr issued. paddr: %h | vaddr: %h", $time, nextAddr, x.vaddr);
        return PendingPrefetch {
            addr: nextAddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule
