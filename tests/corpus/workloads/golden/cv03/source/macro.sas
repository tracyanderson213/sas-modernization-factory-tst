%let table=members;
proc sql; select id from &table; quit;
