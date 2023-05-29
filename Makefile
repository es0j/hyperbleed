all:
	gcc -o victim test.c -O0 -masm=intel -w 		-DVICTIM 
	gcc -o victim-PRCTL test.c -O0 -masm=intel -w 	-DVICTIM  -DPRCTL
	gcc -o victim-nospecctrl test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=0
	gcc -o victim-IBRS test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=1
	gcc -o victim-STIBP test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=2
	gcc -o victim-IBPB test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=0 -DIBPB
	
	gcc -o attacker test.c -O0 -masm=intel -w  

clean:
	rm attacker
	rm victim*
	

	
