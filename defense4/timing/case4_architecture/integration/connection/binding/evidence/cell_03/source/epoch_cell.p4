/* Paired full32 epoch/phase feasibility experiment. Not native admission.
 * Four actions total. A transition uses epoch32 plus packed phase32 (two inputs).
 * No zero-sentinel generation comparison; close/publication serialize in cell.
 */
Register<connection_cell_t,bit<1>>(1,{0,0}) connection_cell;
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) read_cell={
 void apply(inout connection_cell_t v,out bit<32> r){r=v.epoch;}
};
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) claim_cell={
 void apply(inout connection_cell_t v,out bit<32> r){
  if(v.phase==0){v.epoch=m.epoch;v.phase=1;r=32w1;}else{r=32w0;}
 }
};
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) transition_cell={
 void apply(inout connection_cell_t v,out bit<32> r){
  if(v.epoch==m.epoch&&v.phase==(bit<32>)m.phase_word[31:16]){
   v.phase=(bit<32>)m.phase_word[15:0];r=32w1;
  }else{r=32w0;}
 }
};
RegisterAction<connection_cell_t,bit<1>,bit<32>>(connection_cell) close_cell={
 void apply(inout connection_cell_t v,out bit<32> r){
  if(v.epoch==m.epoch){v.phase=7;r=32w1;}else{r=32w0;}
 }
};
