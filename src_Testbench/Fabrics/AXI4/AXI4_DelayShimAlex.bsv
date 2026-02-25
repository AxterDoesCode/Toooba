// DelayShim using transactors
package AXI4_DelayShimAlex;

// ================================================================
// Bluespec library imports

import Vector       :: *;
import FIFOF        :: *;
import SpecialFIFOs :: *;
import ConfigReg    :: *;
import RegFile      ::*;


// ----------------
// BSV additional libs

import Cur_Cycle  :: *;

// ================================================================
// Project imports

import Semi_FIFOF :: *;
import AXI4_Types :: *;
import Fabric_Defs ::*;

// This is the problem  import that is looking for AXI via import Mem::*
//import FF :: *;

// ================================================================

interface AXI4_DelayShim_IFC; 
   interface AXI4_Slave_IFC #(Wd_Id, Wd_Addr, Wd_Data, Wd_User) from_master;
   interface AXI4_Master_IFC #(Wd_Id, Wd_Addr, Wd_Data, Wd_User) to_slave;
endinterface

// ================================================================

// The FF.bsv file in which these live in have some dependencies on BlueStuff/AXI
// Which cannot be used as it conflicts with BlueSpec AXI libraries in src_Testbench
// Hence copy them in
interface FF#(type data, numeric type depth);
  method Action enq(data x);
  method Action deq();
  method data first();
  method Bool notFull();
  method Bool notEmpty();
  method Action clear();
  method Bit#(TAdd#(TLog#(depth), 1)) remaining();
endinterface

// Equal to Bluespec equivelant
module mkUGFF(FF#(data, depth))
provisos(Log#(depth,logDepth),Bits#(data, data_width));
  //staticAssert(valueOf(TExp#(logDepth))==valueOf(depth), "Non Power-of-two FF sizes waste BRAM capacity");
	RegFile#(Bit#(logDepth),data)    rf <- mkRegFileWCF(minBound, maxBound); // BRAM
  Reg#(Bit#(TAdd#(logDepth,1))) lhead <- mkConfigRegA(0);
  Reg#(Bit#(TAdd#(logDepth,1))) ltail <- mkConfigRegA(0);

  Bit#(TAdd#(logDepth,1)) level = lhead - ltail;
  Bool empty = (level==0);
  Bool full  = (level==fromInteger(valueOf(depth)));
  Bit#(logDepth) head = truncate(lhead);
  Bit#(logDepth) tail = truncate(ltail);

  PulseWire displayPanic <- mkPulseWire;
  rule doDisplayPanic (displayPanic);
    $display("Panic!  Enqing to a full UGFF!");
  endrule
  method Action enq(data in);
    if (full) displayPanic.send;
    rf.upd(head,in);
    lhead <= lhead + 1;
  endmethod
  method Action deq();
    ltail <= ltail+1;
  endmethod
  method data first() = rf.sub(tail);
  method Bool notFull() = !full;
  method Bool notEmpty() = !empty;
  method Action clear() = action ltail <= lhead; endaction;
  method Bit#(TAdd#(TLog#(depth), 1)) remaining() = fromInteger(valueOf(depth)) - level;
endmodule

module mkUGFFDelay#(Bit#(16) delay)(FF#(data, depth))
provisos(Log#(depth,logDepth),Bits#(data, data_width));
  RegFile#(Bit#(logDepth),data)    rf <- mkRegFileWCF(minBound, maxBound); // BRAM
  Reg#(Bit#(TAdd#(logDepth,1))) lhead <- mkConfigRegA(0);
  Reg#(Bit#(TAdd#(logDepth,1))) ltail <- mkConfigRegA(0);
  Reg#(Bit#(16))                count <- mkConfigRegA(?);
  FF#(Bit#(16), depth)         delays <- mkUGFF;

  Bit#(TAdd#(logDepth,1)) level = lhead - ltail;
  Bool empty = (level==0);
  Bool full  = (level==fromInteger(valueOf(depth)));
  Bit#(logDepth) head = truncate(lhead);
  Bit#(logDepth) tail = truncate(ltail);

  rule incCount;
    count <= count + 1;
  endrule

  method Action enq(data in);
    if (full) $display("Panic!  Enqing to a full UGFF!");
    delays.enq(count);
    rf.upd(head,in);
    lhead <= lhead + 1;
  endmethod
  method Action deq();
    delays.deq();
    ltail <= ltail+1;
  endmethod
  method data first() = rf.sub(tail);
  method Bool notFull() = !full;
  method Bool notEmpty() = !empty && ((count - delays.first) >= delay);
  method Action clear() = action ltail <= lhead; endaction;
  method Bit#(TAdd#(TLog#(depth), 1)) remaining() = fromInteger(valueOf(depth)) - level;
endmodule

// DelayShim Implementation
module mkAXI4_DelayShim #(Bit #(16) delay) (AXI4_DelayShim_IFC);

   AXI4_Slave_Xactor_IFC  #(Wd_Id, Wd_Addr, Wd_Data, Wd_User)
      xactor_from_master <- mkAXI4_Slave_Xactor;

   AXI4_Master_Xactor_IFC #(Wd_Id, Wd_Addr, Wd_Data, Wd_User)
      xactor_to_slave <- mkAXI4_Master_Xactor;

   // ================================================================
   // FIFOs and Delay FIFOs (mkUGFFDelay)

   FIFOF #(AXI4_Wr_Addr #(Wd_Id, Wd_Addr, Wd_User)) awff <- mkFIFOF;
   FIFOF #(AXI4_Wr_Data #(Wd_Data, Wd_User))        wff  <- mkFIFOF;
   FF #(AXI4_Wr_Resp #(Wd_Id, Wd_User), 128)          bff  <- mkUGFFDelay(delay); // 128 is the depth used in CHERI-Toooba
   FF #(AXI4_Rd_Addr #(Wd_Id, Wd_Addr, Wd_User), 128) arff <- mkUGFFDelay(delay);
   FIFOF #(AXI4_Rd_Data #(Wd_Id, Wd_Data, Wd_User)) rff  <- mkFIFOF;

   //FIFOF #(AXI4_Wr_Addr #(Wd_Id, Wd_Addr, Wd_User))   awff <- mkFIFOF;
   //FIFOF #(AXI4_Wr_Data #(Wd_Data, Wd_User))          wff  <- mkFIFOF;
   //FF #(AXI4_Wr_Resp #(Wd_Id, Wd_User), 128)          bff  <- mkUGFFDelay(delay);
   //FIFOF #(AXI4_Rd_Addr #(Wd_Id, Wd_Addr, Wd_User))   arff <- mkFIFOF;
   //FF #(AXI4_Rd_Data #(Wd_Id, Wd_Data, Wd_User), 128) rff  <- mkUGFFDelay(delay);

   // Sanity check, no delay used everything works fine
   //FIFOF #(AXI4_Wr_Addr #(Wd_Id, Wd_Addr, Wd_User)) awff <- mkFIFOF;
   //FIFOF #(AXI4_Wr_Data #(Wd_Data, Wd_User))        wff  <- mkFIFOF;
   //FIFOF #(AXI4_Wr_Resp #(Wd_Id, Wd_User))          bff  <- mkFIFOF;
   //FIFOF #(AXI4_Rd_Addr #(Wd_Id, Wd_Addr, Wd_User)) arff <- mkFIFOF;
   //FIFOF #(AXI4_Rd_Data #(Wd_Id, Wd_Data, Wd_User)) rff  <- mkFIFOF;

   // ================================================================
   // WRITE ADDRESS (AW)

   rule rl_aw_master_to_delay;
      let aw = xactor_from_master.o_wr_addr.first;
      xactor_from_master.o_wr_addr.deq;
      awff.enq(aw);
   endrule

   rule rl_aw_delay_to_slave;
      let aw = awff.first;
      awff.deq;
      xactor_to_slave.i_wr_addr.enq(aw);
   endrule

   // ================================================================
   // WRITE DATA (W)

   rule rl_w_master_to_delay;
      let w = xactor_from_master.o_wr_data.first;
      xactor_from_master.o_wr_data.deq;
      wff.enq(w);
   endrule

   rule rl_w_delay_to_slave;
      let w = wff.first;
      wff.deq;
      xactor_to_slave.i_wr_data.enq(w);
   endrule

   // ================================================================
   // WRITE RESPONSE (B)

   rule rl_b_slave_to_delay;
      let b <- pop_o(xactor_to_slave.o_wr_resp);
      bff.enq(b);
   endrule

   rule rl_b_delay_to_master;
      let b = bff.first;
      bff.deq;
      xactor_from_master.i_wr_resp.enq(b);
   endrule

   // ================================================================
   // READ ADDRESS (AR)

   rule rl_ar_master_to_delay;
      let ar = xactor_from_master.o_rd_addr.first;
      xactor_from_master.o_rd_addr.deq;
      arff.enq(ar);
   endrule

   rule rl_ar_delay_to_slave;
      let ar = arff.first;
      arff.deq;
      xactor_to_slave.i_rd_addr.enq(ar);
   endrule

   // ================================================================
   // READ DATA (R)

   rule rl_r_slave_to_delay;
      let r <- pop_o(xactor_to_slave.o_rd_data);
      rff.enq(r);
   endrule

   rule rl_r_delay_to_master;
      let r = rff.first;
      rff.deq;
      xactor_from_master.i_rd_data.enq(r);
   endrule

   // ================================================================
   // INTERFACE

   interface from_master = xactor_from_master.axi_side;
   interface to_slave    = xactor_to_slave.axi_side;

endmodule

endpackage
