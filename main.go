package mmh3

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
)

type Hash struct {
	data []byte
}

func (h *Hash) AsBytes() []byte {
	return h.data
}

func (h *Hash) AsUint32() []uint32 {
	switch len(h.data) {
	case 4:
		return []uint32{binary.BigEndian.Uint32(h.data)}
	case 16:
		return []uint32{
			binary.BigEndian.Uint32(h.data[:4]),
			binary.BigEndian.Uint32(h.data[4:8]),
			binary.BigEndian.Uint32(h.data[8:12]),
			binary.BigEndian.Uint32(h.data[12:]),
		}
	}

	return []uint32{}
}

func (h *Hash) AsUint64() []uint64 {
	switch len(h.data) {
	case 4:
		return []uint64{binary.BigEndian.Uint64(h.data)}
	case 16:
		return []uint64{
			binary.BigEndian.Uint64(h.data[:8]),
			binary.BigEndian.Uint64(h.data[8:]),
		}
	}

	return []uint64{}
}

func rotl64(x uint64, r int8) uint64 {
	return (x << r) | (x >> (64 - r))
}

func rotl32(x uint32, r int8) uint32 {
	return (x << r) | (x >> (32 - r))
}

func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= uint64(0xff51afd7ed558ccd)
	k ^= k >> 33
	k *= uint64(0xc4ceb9fe1a85ec53)
	k ^= k >> 33

	return k
}

func fmix32(h uint32) uint32 {
	h ^= h >> 16
	h *= uint32(0x85ebca6b)
	h ^= h >> 13
	h *= uint32(0xc2b2ae35)
	h ^= h >> 16

	return h
}

func Hash32(key string, seed uint32) (Hash, error) {

	out := make([]byte, 4)
	len := len(key)

	nblocks := len / 4

	// var buf bytes.Buffer
	// enc := gob.NewEncoder(&buf)
	// err := enc.Encode(key)
	// if err != nil {
	// 	return nil, err
	// }
	// data := buf.Bytes()

	data := []byte(key)

	h1 := uint32(seed)

	c1 := uint32(0xcc9e2d51)
	c2 := uint32(0x1b873593)

	//----------
	// body

	//const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

	//blocks := data[nblocks*4:]

	for i := 0; i < nblocks; i++ {
		//uint32_t k1 = getblock32(blocks,i);

		var k1 uint32
		err := binary.Read(bytes.NewBuffer(data[(i*4):(i*4)+4]), binary.LittleEndian, &k1)
		if err != nil {
			panic(err)
		}

		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = rotl32(h1, 13)
		h1 = h1*5 + uint32(0xe6546b64)
	}

	//----------
	// tail

	tail := data[nblocks*4:]

	k1 := uint32(0)

	switch len & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		{
			k1 *= c1
			k1 = rotl32(k1, 15)
			k1 *= c2
			h1 ^= k1
		}

	}

	//----------
	// finalization

	h1 ^= uint32(len)

	h1 = fmix32(h1)

	binary.LittleEndian.PutUint32(out[:], h1)

	return Hash{out}, nil
	//*(uint32_t*)out = h1;
}

func Hash128(key string, seed uint32) (Hash, error) {
	out := make([]byte, 16)
	len := len(key)

	nblocks := len / 16

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	if err != nil {
		return Hash{}, err
	}
	data := buf.Bytes()

	h1 := uint64(seed)
	h2 := uint64(seed)

	c1 := uint64(0x87c37b91114253d5)
	c2 := uint64(0x4cf5ad432745937f)

	//----------
	// body

	//const uint64_t * blocks = (const uint64_t *)(data);

	for i := 0; i < nblocks; i++ {
		//option 1
		//k1 := binary.LittleEndian.Uint64(data)
		//option 2 (check errors)
		// var num uint64
		// err := binary.Read(bytes.NewBuffer(data[:]), binary.LittleEndian, &num)
		//option 3 (inverse bytes)
		//k1 := *(*uint64)(unsafe.Pointer(&arr[0]))
		//k2 := *(*uint64)(unsafe.Pointer(&arr[8]))

		var k1 uint64
		var k2 uint64
		err := binary.Read(bytes.NewBuffer(data[:]), binary.LittleEndian, &k1)
		if err != nil {
			return Hash{}, err
		}

		err = binary.Read(bytes.NewBuffer(data[8:]), binary.LittleEndian, &k2)
		if err != nil {
			return Hash{}, err
		}
		//uint64_t k1 = getblock64(blocks,i*2+0);
		//uint64_t k2 = getblock64(blocks,i*2+1);

		k1 *= c1
		k1 = rotl64(k1, 31)
		k1 *= c2
		h1 ^= k1

		h1 = rotl64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = rotl64(k2, 33)
		k2 *= c1
		h2 ^= k2

		h2 = rotl64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	//----------
	// tail

	//const uint8_t * tail = (const uint8_t*)(data + nblocks*16);
	tail := data[nblocks*16:]

	var k1 uint64 = 0
	var k2 uint64 = 0

	switch len & 15 {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8]) << 0
		{
			k2 *= c2
			k2 = rotl64(k2, 33)
			k2 *= c1
			h2 ^= k2
		}
		fallthrough
	case 8:
		k1 ^= uint64(tail[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0]) << 0
		{
			k1 *= c1
			k1 = rotl64(k1, 31)
			k1 *= c2
			h1 ^= k1
		}
	}

	//----------
	// finalization

	h1 ^= uint64(len)
	h2 ^= uint64(len)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1

	binary.LittleEndian.PutUint64(out[:], h1)
	binary.LittleEndian.PutUint64(out[8:], h2)

	return Hash{out}, nil
}
