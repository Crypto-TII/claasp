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
array[0..nbit-1,0..7] of var 0..1: conditions;
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


array[0..nbit-2,0..7] of var 0..1: c1; 
array[0..nbit-2,0..7] of var 0..1: b1; 
array[0..nbit-2,0..7] of var 0..1: c2; 
array[0..nbit-2,0..7] of var 0..1: b2;
array[0..nbit-2,0..7] of var 0..1: c3;

array[0..nbit-1,0..7] of var int: dp_lbct;             
array[0..15] of int: state2index_lbct = array1d(0..15, [0, -1, -1, 1, -1, 2, 3, -1, -1, 4, 5, -1, 6, -1, -1, 7]);

% array[0..15] of var 0..1: dL = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0]);
% array[0..15] of var 0..1: dR = array1d(0..16-1, [1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0]);
% array[0..15] of var 0..1: nL = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: nR = array1d(0..16-1, [0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: nLL = array1d(0..16-1, [1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: dL = array1d(0..16-1, [1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0]);
array[0..15] of var 0..1: dR = array1d(0..16-1, [1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0]);
array[0..15] of var 0..1: nL = array1d(0..16-1, [1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0]);
array[0..15] of var 0..1: nR = array1d(0..16-1, [1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: nLL = array1d(0..16-1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
% bit = 1
%   state = 0: 2 0 0 0 0 0 0 0 
%   state = 1: 0 0 0 0 0 0 0 0 
%   state = 2: 0 0 0 0 0 0 0 0 
%   state = 3: 0 0 0 2 0 0 0 0 
%   state = 4: 0 0 0 0 0 0 0 0 
%   state = 5: 0 0 0 0 0 0 0 0 
%   state = 6: 2 0 0 2 0 0 4 0 
%   state = 7: 0 0 0 0 0 0 0 0 

% bit = 3
%   state = 0: 4 0 0 0 0 2 2 0 
%   state = 1: 0 0 0 0 0 0 0 0 
%   state = 2: 0 0 0 0 0 0 0 0 
%   state = 3: 0 0 0 0 0 0 0 0 
%   state = 4: 0 0 0 0 0 0 0 0 
%   state = 5: 0 0 0 0 0 2 0 0 
%   state = 6: 0 0 0 0 0 0 2 0 
%   state = 7: 0 0 0 0 0 0 0 0 
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
    (c1[i-1,state] = valid_state_lbct[state,0])/\
    (b1[i-1,state] = valid_state_lbct[state,1])/\ 
    (c2[i-1,state] = valid_state_lbct[state,2])/\
    (b2[i-1,state] = valid_state_lbct[state,3]) /\
    (c3[i-1,state] = valid_state_lbct[state,4]) /\
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
  )
);

array[0..nbit-2,0..7,0..31] of var -1..7: index_to_actually_sum;
constraint forall(i in 1..nbit-1) (
forall(j in 0..7)(
    forall(state in 0..7) (
      forall(xy in 0..3) (
        index_to_actually_sum[i-1,j,state*4+xy] = if state2index_lbct[index_dp_t_element_to_sum[i-1,state,xy]] = j then state else -1
        endif
      )
  )
)  
);

array[0..nbit-2,0..7,0..7] of var 0..7: times_to_sum_the_index;
array[0..nbit-2,0..7] of var 0..1: sum_different_from_0;
constraint forall(i in 1..nbit-1) (
  forall(state in 0..7) (
    forall(index in 0..7)(
      times_to_sum_the_index[i-1,state,index] = sum(k in 0..31)(
        if index_to_actually_sum[i-1,state,k] = index then 1 else 0 endif
      )
    )
  ) /\
  forall(state in 0..7)(
    sum_different_from_0[i-1, state] = if sum(index in 0..7)(times_to_sum_the_index[i-1,state,index]) = 0 then 0 else 1 endif
  )
);

% constraint forall(state in 0..7)(conditions[nbit-1,state] = valid_state_lbct[state,0] + valid_state_lbct[state,4] + nLL[1] + nR[1] + nL[1]);

% constraint
%   forall(bit in 0..nbit-2, state in 0..7)(
%     dp_lbct[bit+1,state] =
%       sum(j in 0..7)(
%         times_to_sum_the_index[bit,state,j] * dp_lbct[bit,j]
%       )
   
% );


% bit = 0
%   state = 0: 4 0 0 0 0 2 2 0 
%   state = 1: 0 0 0 0 0 0 0 0 
%   state = 2: 0 0 0 0 0 0 0 0 
%   state = 3: 0 0 0 0 0 0 0 0 
%   state = 4: 0 0 0 0 0 0 0 0 
%   state = 5: 0 0 0 0 0 2 0 0 
%   state = 6: 0 0 0 0 0 0 2 0 
%   state = 7: 0 0 0 0 0 0 0 0 
  
% array[0..7] of var int: dp_final;
% constraint forall(j in 0..7) (
% (sum_different_from_0[nbit-2,j] = 0) -> (dp_final[j] = 0) /\
% (sum_different_from_0[nbit-2,j] = 1) -> (
% dp_final[j] = sum(i in reverse(0..nbit-2), state in 0..7)(
%     if sum_different_from_0[i,j] = 0 then 0 else times_to_sum_the_index[i,j,state]
%     endif
%   )
% )
% );







% var int: lbct_prob;
% constraint lbct_prob = 4 * sum(state in 0..7)(
%     if (valid_state_lbct[state,0] + valid_state_lbct[state,4] + nLL[1] + nR[1] + nL[1]) mod 2 = 0 then
%         dp_lbct[nbit-1,state]
%     else 0
%     endif
% );

% var float: lbct_value = lbct_prob / 2^32;

   
  output [
  concat([ "bit = \(i-1)\n" ++
   concat(["c1[\(i-1),\(state)] = \(c1[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat(["b1[\(i-1),\(state)] = \(b1[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat(["c2[\(i-1),\(state)] = \(c2[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat(["b2[\(i-1),\(state)] = \(b2[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat(["c3[\(i-1),\(state)] = \(c3[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat(["condition[\(i-1),\(state)] = \(conditions[i-1,state]) " | state in 0..7]) ++ "\n" ++
   concat([
          "  state = \(s): \n" ++ concat([
                             "xy = \(xy) -> tmp1 = \(tmp1[i-1,s,xy]) tmp2 = \(tmp2[i-1,s,xy]) tmp3 = \(tmp3[i-1,s,xy]) tmp4 = \(tmp4[i-1,s,xy]) tmp5 = \(tmp5[i-1,s,xy]) \n"| xy in 0..3]) ++ "\n"
         | s in 0..7]) | i in 1..nbit-1]),
  
  concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(index_dp_t_element_to_sum[l,s,xy]) " | xy in 0..3]) ++ "\n"
         | s in 0..7]) ++ "\n"
    | l in 0..nbit-2]),  
% concat([
%       concat(["dp_lbct[\(i-1),\(state)] = \(dp_lbct[i-1,state]) \n" | state in 0..7]) ++ "\n" | i in 1..nbit
%       ]),
%       "lbct_entry/2^32 = \(lbct_value)"
concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(index_to_actually_sum[l,s,xy]) " | xy in 0..31]) ++ "\n"
         | s in 0..7]) ++ "\n"
    | l in 0..nbit-2]),
    
    concat([
    "bit = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(times_to_sum_the_index[l,s,xy]) " | xy in 0..7]) ++ "\n"
         | s in 0..7]) ++ "\n"
    | l in 0..nbit-2]),
    concat([
      concat(["dp_lbct[\(i-1),\(state)] = \(dp_lbct[i-1,state]) \n" | state in 0..7]) ++ "\n" | i in 1..nbit
      ])  
  ];
  
% dp_lbct[15,7] = 1 * dp_lbct[14,1] + 2*dp_lbct[14,7] = 1* 0 + 2*1* dp_lbct[13,5] = 2 * 1 * 2 * dp_lbct[12,5] = .... = 
 % = sum_k=0^7 c_k dp_lbct[0,k] = c_0 * 1
 % 3 * dp_lbct[0,0] + 6*dp_lbct[0,0]
 %  dp_lbct[15,0] = c_0^0
 % dp_lbct[15,1] = c_0^1
