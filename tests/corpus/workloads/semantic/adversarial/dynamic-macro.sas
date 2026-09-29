/* Primary behavior: indirect resolution, quoting, and conditional generation. */
%let selected=west;
%let west_limit=20;
%macro choose(region);
    %let limit=&&&region._limit;
    data work.&region._selected;
        set work.macro_source;
        where region = "%upcase(&region)" and amount >= &limit;
    run;
%mend;
data work.macro_source;
    input id region $ amount;
datalines;
1 WEST 10
2 WEST 20
3 EAST 30
;
run;
%choose(&selected);
