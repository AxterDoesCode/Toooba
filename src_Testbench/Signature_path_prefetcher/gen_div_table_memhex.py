# Configured to divide two n-bit numbers
# Giving an m-bit result value (fixed point representation with m fractional bits)
# Thus the result of the divison must be between 0 and 1.
# This is used for divisions in the Signature Path Prefetcher.

import sys

inWidth = int(sys.argv[1])
outWidth = int(sys.argv[2])
maxValue = int(sys.argv[3], 0) if len(sys.argv) > 3 else (2**outWidth-1)

with open(f"div_table_{inWidth}x{inWidth}to{outWidth}.bsvi", "w") as fout:
    fout.write ("// ***** This file was generated from a script *****\n")
    fout.write ("\n")
    fout.write ("\n")
    fout.write ("// This file is a BSV 'include' file\n")
    fout.write ("\n")
    fout.write ("\n")
    fout.write ("\n")
    fout.write (f"function Bit #({outWidth}) readDivtable{inWidth}x{inWidth}to{outWidth} (Bit #({inWidth*2}) addr);\n")
    fout.write ("   return\n")
    fout.write ("      case (addr)\n")
    addr = 0
    for dividend in range(0, 2**inWidth):
        for divisor in range(0, 2**inWidth):

            if (divisor == 0):
                div = 0
            elif (dividend > divisor):
                div = 1
            else:
                div = float(dividend) / float(divisor)
            div = div * (2**outWidth)
            div = round(div)
            div = min(div, maxValue)
            divstr = '{0:07b}'.format(div)
            print(dividend, divisor, divstr)
            #f.write("1111111\n")   
            fout.write(f"            {addr}: 7'b_{divstr};\n")
            addr += 1
    fout.write ("         default: 7'h0;\n")
    fout.write ("      endcase;\n")
    fout.write (f"endfunction: readDivtable{inWidth}x{inWidth}to{outWidth}\n")
    fout.write ("\n")
