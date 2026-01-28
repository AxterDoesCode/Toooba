import TlbTypes ::* ;
import CCTypes ::* ;
interface CDP#(type reqT);
    method Action vaddrMatcher(reqT req, Line line);
    // Virtual address matcher supposed to pass in the type as the crqType thing,
    // Rather than passing in the VPN pass in the whole request.
endinterface
module mkCdp(CDP);
    method Action vaddrMatcher(Vpn vpn, Line line);
        //Line curLine = ram.line;
        //Line newLine = curLine;
        LineDataOffset dataSel = getLineDataOffset(req.addr);
    endmethod
endmodule
