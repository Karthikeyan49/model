PROGRAM arr_oob_2
VAR
  tank_levels : ARRAY[0..3] OF REAL;
  idx : INT;
END_VAR
tank_levels[idx + 2] := 99.0;
END_PROGRAM
