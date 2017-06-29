HoneywordsM/ProVerif

This folder contains the formal models of the Honeywords System's protocols mentioned in the paper "A Secure Honeywords System Despite a Code-Corrupted Login Server". This paper is submission number 255 to ESORICS 2017.
The code is intended to be analysed using ProVerif verifier (http://prosecco.gforge.inria.fr/personal/bblanche/proverif/).
It contains also the results of the automatic verification of the source models.


----------------------
FILES

In the 'src' folder:

 + originalHw.pv : The code of the model described in section "5.1 Analysis of the original Honeywords System protocol". It corresponds to the original Honeywords system, as proposed in [1].
 + newProtocolOTP.pv : The model of the solution proposed in Section 4 of the paper 255. This code is used for the analysis in section "5.2 Analysis of the new protocol"
 + newProtocolOTPnotAtomic.pv : A modified version of the model in 'newProtocolOTP.pv'; here, the HC processes multiple requests of LS in parallel. This code is mentioned in section "5.2 Analysis of the new protocol"

In the 'Results' folder:

 + traceCodCorr.pdf contains the attack found in the verification of "originalHw.pv" 
 + traceNotAtomic.pdf contains the attack found in the verification of "newProtocolOTPnotAtomic.pv"


-----------------------
EXECUTION

The code can be executed with a Proverif installation as follows:

To get only the final result:
	$ proverif  originalHw.pv | grep RES
	$ proverif  newProtocolOTP.pv | grep RES
	$ proverif  newProtocolOTPnotAtomic.pv | grep RES
	
For the files where properties are false:
To get an explained trace:
	$ proverif -color originalHw.pv

To generate a PDF with the trace (the PDF will be saved in the Results folder):
	$ proverif -color -graph Results/ originalHw.pv
	

-----------------------------	
REFERENCES
[1] Juels, A., Rivest, R.L.: Honeywords: Making password-cracking detectable. In: Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. pp. 145{160. ACM (2013)
