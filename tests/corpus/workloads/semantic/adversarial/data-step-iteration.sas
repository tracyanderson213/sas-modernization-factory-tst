/* Primary behavior: PDV reset, sum retention, explicit RETAIN, and conditional OUTPUT. */
data work.iteration;
    retain retained 100;
    input id value;
    sum_statement + value;
    if id = 1 then reset_each_iteration = value * 2;
    retained + 1;
    if mod(id, 2) = 0 then output;
datalines;
1 10
2 20
3 30
4 40
;
run;
