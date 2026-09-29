/* SMF-authored synthetic oracle: exact SAS date/datetime literal values and formats. */
proc sql;
    create table work.temporal_literals as
    select '01JAN1960'd as epoch_day format=date9.,
           '31DEC1959'd as before_epoch format=date9.,
           '29FEB2000'd as leap_day format=date9.,
           '01JAN1960:00:00:00.123400'dt as fractional_ts format=datetime26.6;
quit;
