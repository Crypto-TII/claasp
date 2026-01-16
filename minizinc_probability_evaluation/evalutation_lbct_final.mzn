array[0..7,0..4] of var 0..1: valid_state_lbct = array2d(0..7,0..4,
[
0,0,0,0,0,%lsb is the first one, msb the last one
1,1,0,0,0,
1,0,1,0,0,
0,1,1,0,0,
1,0,0,1,0,
0,1,0,1,0,
0,0,1,1,0,
1,1,1,1,0
]);
int: nbit = 16;
% array[0..nbit-2,0..7] of var 0..1: c1; 
% array[0..nbit-2,0..7] of var 0..1: b1; 
% array[0..nbit-2,0..7] of var 0..1: c2; 
% array[0..nbit-2,0..7] of var 0..1: b2;
% array[0..nbit-2,0..7] of var 0..1: c3;

array[0..nbit-2,0..7] of var 0..1: conditions;
array[0..nbit-2,0..7,0..3] of var 0..15: index_dp_t_element_to_sum;
array[0..3,0..1] of 0..1: xy_array = array2d(0..3,0..1,
[
0,0,
0,1,
1,0,
1,1
]);

array[0..nbit-2, 0..7, 0..3] of var 0..1: tmp1;
array[0..nbit-2, 0..7, 0..3] of var 0..1: tmp2;
array[0..nbit-2, 0..7, 0..3] of var 0..1: tmp3;
array[0..nbit-2, 0..7, 0..3] of var 0..1: tmp4;
array[0..nbit-2, 0..7, 0..3] of var 0..1: tmp5;

array[0..nbit-1,0..7] of var int: dp_lbct; 
array[0..15] of int: state2index_lbct = array1d(0..15, [0, -1, -1, 1, -1, 2, 3, -1, -1, 4, 5, -1, 6, -1, -1, 7]);

array[0..15] of var 0..1: dL = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0]);
array[0..15] of var 0..1: dR = array1d(0..16-1, [1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0]);
array[0..15] of var 0..1: nL = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: nR = array1d(0..16-1, [0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: nLL = array1d(0..16-1, [1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);

constraint dp_lbct[0,0] = 1;
constraint dp_lbct[0,1] = 0;
constraint dp_lbct[0,2] = 0;
constraint dp_lbct[0,3] = 0;
constraint dp_lbct[0,4] = 0;
constraint dp_lbct[0,5] = 0;
constraint dp_lbct[0,6] = 0;
constraint dp_lbct[0,7] = 0;

constraint  forall(i in 1..nbit-1)(
    forall(state in 0..7)( 
%     (c1[i-1,state] = valid_state_lbct[state,0])/\
%     (b1[i-1,state] = valid_state_lbct[state,1])/\ 
%     (c2[i-1,state] = valid_state_lbct[state,2])/\
%     (b2[i-1,state] = valid_state_lbct[state,3]) /\
%     (c3[i-1,state] = valid_state_lbct[state,4]) /\
    (conditions[i-1,state] = (valid_state_lbct[state,0] + valid_state_lbct[state,4]+nLL[nbit-i]+nL[nbit-i]+nR[nbit-i]) mod 2) /\
    ((conditions[i-1,state] = 1) -> forall(xy in 0..3) (index_dp_t_element_to_sum[i-1,state,xy] = 1)) /\
    ((conditions[i-1,state] = 0) -> 
        forall(xy in 0..3) (
            (tmp1[i-1,state,xy] = (xy_array[xy,0]*xy_array[xy,1] + xy_array[xy,0]*valid_state_lbct[state,0] + xy_array[xy,1]*valid_state_lbct[state,0]) mod 2)/\
            (tmp2[i-1,state,xy] =
                      min(1,
                        (((xy_array[xy,0]+xy_array[xy,1]+valid_state_lbct[state,0]+nL[nbit-i]+1) mod 2)*((xy_array[xy,1]+nR[nbit-i]) mod 2))+
                        (((xy_array[xy,0]+xy_array[xy,1]+valid_state_lbct[state,0]+nL[nbit-i]+1) mod 2)*valid_state_lbct[state,1])+
                        (((xy_array[xy,0]+xy_array[xy,1]+valid_state_lbct[state,0]+nL[nbit-i]) mod 2)*((xy_array[xy,1]+nR[nbit-i]) mod 2)*valid_state_lbct[state,1])
                      ) 
            )/\
            (tmp3[i-1,state,xy] = 
                  (
                    (((xy_array[xy,0]+dL[nbit-i]) mod 2)*((xy_array[xy,1]+dR[nbit-i]) mod 2))+
                    (((xy_array[xy,0]+dL[nbit-i]) mod 2)*valid_state_lbct[state,2])+
                    (((xy_array[xy,1]+dR[nbit-i]) mod 2)*valid_state_lbct[state,2])
                  ) mod 2
            )/\
            (tmp4[i-1,state,xy] = 
                      min(1,
                          (
                            ((xy_array[xy,0]+dL[nbit-i]+xy_array[xy,1]+dR[nbit-i]+valid_state_lbct[state,2]+nL[nbit-i]+1) mod 2)*((xy_array[xy,1]+dR[nbit-i]+nR[nbit-i]) mod 2)
                          )+
                          (((xy_array[xy,0]+dL[nbit-i]+xy_array[xy,1]+dR[nbit-i]+valid_state_lbct[state,2]+nL[nbit-i]+1) mod 2)*valid_state_lbct[state,3])+
                          (
                            ((xy_array[xy,0]+dL[nbit-i]+xy_array[xy,1]+dR[nbit-i]+valid_state_lbct[state,2]+nL[nbit-i]) mod 2)*((xy_array[xy,1]+dR[nbit-i]+nR[nbit-i]) mod 2)*valid_state_lbct[state,3]
                           )
                      )
            )/\
            (tmp5[i-1,state,xy] = 
                  (
                    (((xy_array[xy,0]+nLL[nbit-i]) mod 2)*((xy_array[xy,1]+nR[nbit-i]) mod 2))+
                    (((xy_array[xy,0]+nLL[nbit-i]) mod 2)*valid_state_lbct[state,4])+
                    (((xy_array[xy,1]+nR[nbit-i]) mod 2)*valid_state_lbct[state,4])
                  ) mod 2
            )/\
            index_dp_t_element_to_sum[i-1,state,xy] = 
                  if tmp5[i-1,state,xy]=0 then tmp4[i-1,state,xy]*8 + tmp3[i-1,state,xy]*4 + tmp2[i-1,state,xy]*2 + tmp1[i-1,state,xy]
                                          else ((tmp4[i-1,state,xy]+1) mod 2)*8 +
                                               ((tmp3[i-1,state,xy]+1) mod 2)*4 +
                                               ((tmp2[i-1,state,xy]+1) mod 2)*2 +
                                               ((tmp1[i-1,state,xy]+1) mod 2)
                  endif
        )
    )
  )/\
  forall(j in 0..7) (
    dp_lbct[i,j] = sum(state in 0..7, xy in 0..3) (
        if state2index_lbct[index_dp_t_element_to_sum[i-1,state,xy]] = j then dp_lbct[i-1,state]
                                                                         else 0 
        endif
    )
  )
);

var int: lbct_prob;
constraint lbct_prob = 4 * sum(state in 0..7)(
    if (valid_state_lbct[state,0] + valid_state_lbct[state,4] + nLL[1] + nR[1] + nL[1]) mod 2 = 0 then
        dp_lbct[nbit-1,state]
    else 0
    endif
);

var float: lbct_value = lbct_prob / 2^32;

   
  output [
  concat([
%    concat(["c1[\(i-1),\(state)] = \(c1[i-1,state]) " | state in 0..7]) ++ "\n" ++
%    concat(["b1[\(i-1),\(state)] = \(b1[i-1,state]) " | state in 0..7]) ++ "\n" ++
%    concat(["c2[\(i-1),\(state)] = \(c2[i-1,state]) " | state in 0..7]) ++ "\n" ++
%    concat(["b2[\(i-1),\(state)] = \(b2[i-1,state]) " | state in 0..7]) ++ "\n" ++
%    concat(["c3[\(i-1),\(state)] = \(c3[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat(["condition[\(i-1),\(state)] = \(conditions[i-1,state]) " | state in 0..7]) ++ "\n" | i in 1..nbit-1]),
  concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(index_dp_t_element_to_sum[l,s,xy]) " | xy in 0..3]) ++ "\n"
         | s in 0..7]) ++ "\n"
    | l in 0..nbit-2]),  
    concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): \n" ++ concat([
                             "xy = \(xy) -> tmp1 = \(tmp1[l,s,xy]) tmp2 = \(tmp2[l,s,xy]) tmp3 = \(tmp3[l,s,xy]) tmp4 = \(tmp4[l,s,xy]) \n"| xy in 0..3]) ++ "\n"
         | s in 0..7]) ++ "\n"
    | l in 0..nbit-2]),
concat([
      concat(["dp_lbct[\(i-1),\(state)] = \(dp_lbct[i-1,state]) \n" | state in 0..7]) ++ "\n" | i in 1..nbit
      ]),
      "lbct_entry/2^32 = \(lbct_value)"
  
  ];
