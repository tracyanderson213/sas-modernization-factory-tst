/* Primary behavior: PROC SQL duplicate multiplicity and missing-key equality. */
data work.sql_left; input key value_left; datalines;
1 10
1 11
. 12
;
run;
data work.sql_right; input key value_right; datalines;
1 20
1 21
. 22
;
run;
proc sql;
    create table work.many_sql as
    select l.key, l.value_left, r.value_right
    from work.sql_left l inner join work.sql_right r on l.key = r.key;
quit;
