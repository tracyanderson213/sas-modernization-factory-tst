/* Primary behavior: SAS ordinary/special missing ordering and summary semantics. */
data work.missing_ordering;
    length label $9;
    input label $ value;
    less_than_zero = value < 0;
    propagated = value + 1;
    summary_sum = sum(value, 1);
datalines;
ordinary .
special_a .A
special_z .Z
negative -1
;
run;
proc sort data=work.missing_ordering; by value; run;
