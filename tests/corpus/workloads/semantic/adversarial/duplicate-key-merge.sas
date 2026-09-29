/* Primary behavior: DATA-step duplicate-key match merge is not a Cartesian join. */
data work.left; input key $ left_value $; datalines;
A L1
A L2
A L3
;
run;
data work.right; input key $ right_value $; datalines;
A R1
A R2
;
run;
data work.duplicate_merge;
    merge work.left work.right;
    by key;
run;
