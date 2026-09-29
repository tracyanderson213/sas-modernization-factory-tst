%macro member_rules(source=, target=);
data &target.;
    set &source.;
    if active_flag = 1;
run;
%mend;
