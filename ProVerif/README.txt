HoneywordsM/ProVerif

This folder contains the formal models of the Honeywords System's protocols mentioned in the paper "A Secure Honeywords System Despite a Code-Corrupted Login Server" and those addressed in the extended version "A Critical Security Analysis of the Password-based Authentication Honeywords System Under Code-Corruption Attack".
The code is intended to be analysed using the ProVerif verifier (http://prosecco.gforge.inria.fr/personal/bblanche/proverif/).
It contains also the results of the automatic verification of the source models.


----------------------
FILES
The 'src' folder contains the models related to the Authentication protocols discussed in the paper published by ICISSP. 'Results' includes the attack traces found for the models in 'src'.

In 'ccis18' are the formal models for the Setup and Change of password protocols addressed in the extended version, including the attacks found.


-----------------------------	
REFERENCES
[1] Juels, A., Rivest, R.L.: Honeywords: Making password-cracking detectable. In: Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. pp. 145{160. ACM (2013)
