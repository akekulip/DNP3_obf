/* Paired full32 epoch/phase feasibility experiment. Not native admission.
 * Four actions total. A transition uses epoch32 plus full expected phase32 (two inputs).
 * Wrapper must restrict advance expectations to bounded1..10, never MAX.
 * Claim requires actual zero work/original debt derivation; diagnostic header
 * here is a feasibility input, never a production proof.
 * No zero-sentinel generation comparison; close/publication serialize in cell.
 */
Register<connection_cell_t,bit<1>>(1,{0,0xffffffff}) connection_cell;
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) read_cell={
 void apply(inout connection_cell_t v,out bit<32> r){r=v.epoch;}
};
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) claim_cell={
 void apply(inout connection_cell_t v,out bit<32> r){
  if(v.phase==32w0xffffffff&&m.expected==32w0){v.epoch=m.epoch;v.phase=1;r=32w1;}else{r=32w0;}
 }
};
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) transition_cell={
 void apply(inout connection_cell_t v,out bit<32> r){
  if(v.epoch==m.epoch&&v.phase==m.expected){
   v.phase=v.phase+32w1;r=32w1;
  }else{r=32w0;}
 }
};
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) close_cell={
 void apply(inout connection_cell_t v,out bit<32> r){
  if(v.epoch==m.epoch){v.phase=32w0xffffffff;r=32w1;}else{r=32w0;}
 }
};
