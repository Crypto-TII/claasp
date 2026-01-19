array[0..3,0..3] of 0..1: valid_state_ubct = array2d(0..3,0..3,
 [ 0,0,0,0, %lsb is the first one, msb the last one
   1,1,0,0,
   1,0,1,0,
   0,1,1,0
]);
int: nbit = 16;
array[0..nbit-1,0..3] of var 0..1: conditions;
array[0..nbit-2,0..3,0..3] of var 0..15: index_dp_t_element_to_sum;
array[0..3,0..1] of 0..1: xy_array = array2d(0..3,0..1,
[
0,0,
0,1,
1,0,
1,1
]);

array[0..nbit-2, 0..3, 0..3] of var 0..1: tmp1;
array[0..nbit-2, 0..3, 0..3] of var 0..1: tmp2;
array[0..nbit-2, 0..3, 0..3] of var 0..1: tmp3;
array[0..nbit-2, 0..3, 0..3] of var 0..1: tmp4;

array[0..nbit-2,0..7] of var 0..1: c1; 
array[0..nbit-2,0..7] of var 0..1: b1; 
array[0..nbit-2,0..7] of var 0..1: c2; 
array[0..nbit-2,0..7] of var 0..1: b2;

array[0..nbit-1,0..3] of var int: dp_ubct;             
array[0..7] of int: state2index_ubct = array1d(0..7, [0, -1, -1, 1, -1, 2, 3, -1]);

% array[0..15] of var 0..1: dL = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: dR = array1d(0..16-1, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: nL = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0]);
% array[0..15] of var 0..1: nR = array1d(0..16-1, [0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0]);
% array[0..15] of var 0..1: dLL = array1d(0..16-1,[1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);

array[0..15] of var 0..1: dL = array1d(0..16-1, [1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1]);
array[0..15] of var 0..1: dR = array1d(0..16-1, [1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,1]);
array[0..15] of var 0..1: nL = array1d(0..16-1, [1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,1]);
array[0..15] of var 0..1: nR = array1d(0..16-1, [1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,1]);
array[0..15] of var 0..1: dLL = array1d(0..16-1,[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);

constraint dp_ubct[0,0] = 1;
constraint dp_ubct[0,1] = 0;
constraint dp_ubct[0,2] = 0;
constraint dp_ubct[0,3] = 0;

constraint  forall(i in 1..nbit-1)(
    forall(state in 0..3)( 
    (conditions[i-1,state] = (valid_state_ubct[state,0] + valid_state_ubct[state,2]+dLL[nbit-i]+dL[nbit-i]+dR[nbit-i]) mod 2) /\
    ((conditions[i-1,state] = 1) -> forall(xy in 0..3) (index_dp_t_element_to_sum[i-1,state,xy] = 1)) /\
    ((conditions[i-1,state] = 0) -> 
        forall(xy in 0..3) (
            (tmp1[i-1,state,xy] = (xy_array[xy,0]*xy_array[xy,1] + xy_array[xy,0]*valid_state_ubct[state,0] + xy_array[xy,1]*valid_state_ubct[state,0]) mod 2)/\
            (tmp2[i-1,state,xy] =
                      min(1,
                        (((xy_array[xy,0]+xy_array[xy,1]+valid_state_ubct[state,0]+nL[nbit-i]+1) mod 2)*((xy_array[xy,1]+nR[nbit-i]) mod 2))+
                        (((xy_array[xy,0]+xy_array[xy,1]+valid_state_ubct[state,0]+nL[nbit-i]+1) mod 2)*valid_state_ubct[state,1])+
                        (((xy_array[xy,0]+xy_array[xy,1]+valid_state_ubct[state,0]+nL[nbit-i]) mod 2)*((xy_array[xy,1]+nR[nbit-i]) mod 2)*valid_state_ubct[state,1])
                      ) 
            )/\
            (tmp3[i-1,state,xy] = 
                  (
                    (((xy_array[xy,0]+dL[nbit-i]) mod 2)*((xy_array[xy,1]+dR[nbit-i]) mod 2))+
                    (((xy_array[xy,0]+dL[nbit-i]) mod 2)*valid_state_ubct[state,2])+
                    (((xy_array[xy,1]+dR[nbit-i]) mod 2)*valid_state_ubct[state,2])
                  ) mod 2
            )/\
            (tmp4[i-1,state,xy] = 
                      min(1,
                          (
                            ((xy_array[xy,0]+dL[nbit-i]+xy_array[xy,1]+dR[nbit-i]+valid_state_ubct[state,2]+nL[nbit-i]+1) mod 2)*((xy_array[xy,1]+dR[nbit-i]+nR[nbit-i]) mod 2)
                          )+
                          (((xy_array[xy,0]+dL[nbit-i]+xy_array[xy,1]+dR[nbit-i]+valid_state_ubct[state,2]+nL[nbit-i]+1) mod 2)*valid_state_ubct[state,3])+
                          (
                            ((xy_array[xy,0]+dL[nbit-i]+xy_array[xy,1]+dR[nbit-i]+valid_state_ubct[state,2]+nL[nbit-i]) mod 2)*((xy_array[xy,1]+dR[nbit-i]+nR[nbit-i]) mod 2)*valid_state_ubct[state,3]
                           )
                      )
            )/\
            index_dp_t_element_to_sum[i-1,state,xy] = 
                  if tmp4[i-1,state,xy]=0 then tmp3[i-1,state,xy]*4 + tmp2[i-1,state,xy]*2 + tmp1[i-1,state,xy]
                                          else ((tmp3[i-1,state,xy]+1) mod 2)*4 +
                                               ((tmp2[i-1,state,xy]+1) mod 2)*2 +
                                               ((tmp1[i-1,state,xy]+1) mod 2)
                  endif
        )
    )
  )
);

array[0..nbit-2,0..3,0..15] of var -1..3: index_to_actually_sum;
constraint forall(i in 1..nbit-1) (
forall(j in 0..3)(
    forall(state in 0..3) (
      forall(xy in 0..3) (
        index_to_actually_sum[i-1,j,state*4+xy] = if state2index_ubct[index_dp_t_element_to_sum[i-1,state,xy]] = j then state else -1
        endif
      )
  )
)  
);

array[0..nbit-2,0..3,0..3] of var int: times_to_sum_the_index;
constraint forall(i in 1..nbit-1) (
  forall(state in 0..3) (
    forall(index in 0..3)(
      times_to_sum_the_index[i-1,state,index] = sum(k in 0..15)(
        if index_to_actually_sum[i-1,state,k] = index then 1 else 0 endif
      )
    )
  )
);


  output [ 
concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(index_to_actually_sum[l,s,xy]) " | xy in 0..15]) ++ "\n"
         | s in 0..3]) ++ "\n"
    | l in 0..nbit-2]),
    
    concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(times_to_sum_the_index[l,s,xy]) " | xy in 0..3]) ++ "\n"
         | s in 0..3]) ++ "\n"
    | l in 0..nbit-2])
  ];




