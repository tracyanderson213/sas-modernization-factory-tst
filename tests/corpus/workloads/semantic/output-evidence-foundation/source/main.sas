data work.positive_amounts;
    set work.transactions;
    if amount > 0;
run;
