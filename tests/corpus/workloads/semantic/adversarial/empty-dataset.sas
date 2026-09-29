/* Primary behavior: zero-row DATA step preserves schema and executes no BY groups. */
data work.empty_input;
    length group $4 value 8;
    stop;
run;
data work.empty_result;
    set work.empty_input;
    by group;
    if first.group then value = 1;
run;
