"""SPARX family of ARX block primitives."""

from claasp_next.graph import Primitive

from ._word_graph import add, concatenate, constant, join_words, rotate, select, split_word, word_type, xor


PARAMETERS = {(64,128):(8,3), (128,128):(8,4), (128,256):(10,4)}


class SPARX(Primitive):
    """SPARX-64/128, SPARX-128/128, or SPARX-128/256."""

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=None, steps=None):
        if (block_bit_size,key_bit_size) not in PARAMETERS:
            raise ValueError("unsupported SPARX parameter set")
        default_rounds, default_steps = PARAMETERS[(block_bit_size,key_bit_size)]
        rounds = default_rounds if number_of_rounds is None else number_of_rounds
        arx_rounds = default_steps if steps is None else steps
        if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
            raise ValueError("number_of_rounds must be a positive integer")
        if not isinstance(arx_rounds, int) or isinstance(arx_rounds, bool) or arx_rounds <= 0:
            raise ValueError("steps must be a positive integer")
        word_count, key_count = block_bit_size//32, key_bit_size//32
        super().__init__("sparx", {"plaintext":word_type(32,word_count), "key":word_type(32,key_count)})
        state=[select(self.input("plaintext"),i) for i in range(word_count)]
        key=[select(self.input("key"),i) for i in range(key_count)]

        def halves(value):
            split=split_word(self,value,16); return select(split,0),select(split,1)
        def combine(high,low): return join_words(self,(high,low),32)
        def arx(value):
            high,low=halves(value)
            new_high=add(self,rotate(self,high,7),low)
            return combine(new_high,xor(self,rotate(self,low,-2),new_high))
        def k4_64(values,r):
            k1=arx(values[0]); k1h,k1l=halves(k1); old1h,old1l=halves(values[1])
            k2=combine(add(self,old1h,k1h),add(self,old1l,k1l))
            k3h,k3l=halves(values[3]); k0=combine(k3h,add(self,k3l,constant(self,16,r)))
            return [k0,k1,k2,values[2]]
        def k4_128(values,r):
            k1=arx(values[0]); k1h,k1l=halves(k1); old1h,old1l=halves(values[1])
            k2=combine(add(self,old1h,k1h),add(self,old1l,k1l))
            k3=arx(values[2]); k3h,k3l=halves(k3); old3h,old3l=halves(values[3])
            k0=combine(add(self,old3h,k3h),add(self,old3l,k3l,constant(self,16,r)))
            return [k0,k1,k2,k3]
        def k8_256(values,r):
            k3=arx(values[0]); k3h,k3l=halves(k3); v1h,v1l=halves(values[1])
            k4=combine(add(self,k3h,v1h),add(self,k3l,v1l))
            k7=arx(values[4]); k7h,k7l=halves(k7); v5h,v5l=halves(values[5])
            k0=combine(add(self,k7h,v5h),add(self,k7l,v5l,constant(self,16,r)))
            return [k0,values[6],values[7],k3,k4,values[2],values[3],k7]
        key_update = k4_64 if block_bit_size==64 else (k4_128 if key_bit_size==128 else k8_256)

        def diffusion(values):
            if len(values)==2:
                x,y=values
                return [xor(self,y,x,rotate(self,x,-8),rotate(self,x,8)),x]
            x,y=values[:2]
            t=xor(self,rotate(self,xor(self,x,y),8),rotate(self,xor(self,x,y),-8))
            high,low=xor(self,x,t),xor(self,y,t)
            hh,hl=halves(high); lh,ll=halves(low)
            new_x,new_y=combine(lh,hl),combine(hh,ll)
            return [xor(self,values[2],new_x),xor(self,values[3],new_y),x,y]

        for round_number in range(rounds):
            self.add_round()
            updated=[]
            for index,value in enumerate(state):
                for arx_round in range(arx_rounds): value=arx(xor(self,value,key[arx_round]))
                updated.append(value)
                key=key_update(key,round_number*word_count+index+1)
            state=diffusion(updated)
        state=[xor(self,value,key[index]) for index,value in enumerate(state)]
        self.set_output(concatenate(self,*state))
