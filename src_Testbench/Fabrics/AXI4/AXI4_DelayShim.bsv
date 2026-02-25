// DelayShim using transactors
package AXI4_DelayShim;

import Vector       :: *;
import FIFOF        :: *;
import SpecialFIFOs :: *;
import ConfigReg    :: *;
import Cur_Cycle    :: *;

import AXI4_Types   :: *;
import FF           :: *;

// ================================================================

interface AXI4_DelayShim_IFC #(numeric type wd_id,
                               numeric type wd_addr,
                               numeric type wd_data,
                               numeric type wd_user);
   method Action reset;

   interface AXI4_Slave_IFC #(wd_id, wd_addr, wd_data, wd_user) from_master;
   interface AXI4_Master_IFC #(wd_id, wd_addr, wd_data, wd_user) to_slave;
endinterface

// ================================================================

module mkAXI4_DelayShim #(Bit #(16) delay)
   (AXI4_DelayShim_IFC #(wd_id, wd_addr, wd_data, wd_user));

   Reg #(Bool) rg_reset <- mkReg(True);

   AXI4_Slave_Xactor_IFC  #(wd_id, wd_addr, wd_data, wd_user)
      xactor_from_master <- mkAXI4_Slave_Xactor;

   AXI4_Master_Xactor_IFC #(wd_id, wd_addr, wd_data, wd_user)
      xactor_to_slave <- mkAXI4_Master_Xactor;

   // ================================================================
   // Delay elements (UGFFDelay)

   FF #(AXI4_Wr_Addr #(wd_id, wd_addr, wd_user)) awff <- mkFIFOF;
   FF #(AXI4_Wr_Data #(wd_data, wd_user))        wff  <- mkFIFOF;
   FF #(AXI4_Wr_Resp #(wd_id, wd_user))         bff  <- mkUGFFDelay(delay);
   FF #(AXI4_Rd_Addr #(wd_id, wd_addr, wd_user)) arff <- mkUGFFDelay(delay);
   FF #(AXI4_Rd_Data #(wd_id, wd_data, wd_user)) rff  <- mkFIFOF;

   // ================================================================
   // RESET

   rule rl_reset (rg_reset);
      xactor_from_master.reset;
      xactor_to_slave.reset;

      awff.clear;
      wff.clear;
      bff.clear;
      arff.clear;
      rff.clear;

      rg_reset <= False;
   endrule

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

   method Action reset () if (!rg_reset);
      rg_reset <= True;
   endmethod

   interface from_master = xactor_from_master.axi_side;
   interface to_slave    = xactor_to_slave.axi_side;

endmodule

endpackage
