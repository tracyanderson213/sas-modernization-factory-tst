/* SMF-authored semantic fixture: macro definition, parameters, variables, and invocation. */
%macro summarize(input=, output=, threshold=);
    data &input;
        input member_id $ paid_amount;
    datalines;
M001 600
M001 500
M002 999
M003 1200
;
    run;

    proc sql;
        create table &output as
        select member_id,
               sum(paid_amount) as total_paid
        from &input
        group by member_id
        having calculated total_paid >= &threshold;
    quit;
%mend summarize;

%summarize(
    input=work.claims,
    output=work.high_cost_members,
    threshold=1000
);
