/* Primary behavior: SAS epoch, leap/year boundaries, INTCK/INTNX, and YEARCUTOFF. */
options yearcutoff=1920;
data work.date_boundaries;
    epoch = '01JAN1960'd;
    leap_day = '29FEB2024'd;
    next_year = intnx('year', '31DEC2023'd, 1, 'same');
    year_boundaries = intck('year', '31DEC2023'd, '01JAN2024'd);
    parsed_two_digit = input('01JAN20', date7.);
    output;
    format epoch leap_day next_year parsed_two_digit date9.;
run;
