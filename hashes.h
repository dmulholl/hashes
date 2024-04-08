#ifndef hashes_h
#define hashes_h

#include <stddef.h>
#include <stdint.h>

// String hash: DJB2, 32-bit version.
static inline uint32_t hash_djb2_32(const uint8_t* string, size_t length) {
    uint32_t hash = UINT32_C(5381);

    // Function: hash(i) = hash(i - 1) * 33 + string[i]
    for (size_t i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + string[i];
    }

    return hash;
}

// String hash: DJB2, 64-bit version.
static inline uint64_t hash_djb2_64(const uint8_t* string, size_t length) {
    uint64_t hash = UINT64_C(5381);

    // Function: hash(i) = hash(i - 1) * 33 + string[i]
    for (size_t i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + string[i];
    }

    return hash;
}

// String hash: DJB2 with XOR, 32-bit version.
static inline uint32_t hash_djb2_32_xor(const uint8_t* string, size_t length) {
    uint32_t hash = UINT32_C(5381);

    // Function: hash(i) = (hash(i - 1) * 33) XOR string[i]
    for (size_t i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) ^ string[i];
    }

    return hash;
}

// String hash: DJB2 with XOR, 64-bit version.
static inline uint64_t hash_djb2_64_xor(const uint8_t* string, size_t length) {
    uint64_t hash = UINT64_C(5381);

    // Function: hash(i) = (hash(i - 1) * 33) XOR string[i]
    for (size_t i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) ^ string[i];
    }

    return hash;
}

// String hash: FNV-1a, 32-bit version.
static inline uint32_t hash_fnv1a_32(const uint8_t* string, size_t length) {
    uint32_t hash = UINT32_C(2166136261);

    // Function: hash(i) = (hash(i - 1) XOR string[i]) * 16777619
    for (size_t i = 0; i < length; i++) {
        hash ^= string[i];
        hash *= 16777619;
    }

    return hash;
}

// String hash: FNV-1a, 64-bit version.
static inline uint64_t hash_fnv1a_64(const uint8_t* string, size_t length) {
    uint64_t hash = UINT64_C(14695981039346656037);

    // Function: hash(i) = (hash(i - 1) XOR string[i]) * 1099511628211
    for (size_t i = 0; i < length; i++) {
        hash ^= string[i];
        hash *= UINT64_C(1099511628211);
    }

    return hash;
}

// String hash: FNV-1a, 32-bit version with optimized multiplication.
static inline uint32_t hash_fnv1a_32_opt(const uint8_t* string, size_t length) {
    uint32_t hash = UINT32_C(2166136261);

    // Function: hash(i) = (hash(i - 1) XOR string[i]) * 16777619
    for (size_t i = 0; i < length; i++) {
        hash ^= string[i];
        hash += (hash<<1) + (hash<<4) + (hash<<7) + (hash<<8) + (hash<<24);
    }

    return hash;
}

// String hash: FNV-1a, 64-bit version with optimized multiplication.
static inline uint64_t hash_fnv1a_64_opt(const uint8_t* string, size_t length) {
    uint64_t hash = UINT64_C(14695981039346656037);

    // Function: hash(i) = (hash(i - 1) XOR string[i]) * 1099511628211
    for (size_t i = 0; i < length; i++) {
        hash ^= string[i];
        hash += (hash<<1) + (hash<<4) + (hash<<5) + (hash<<7) + (hash<<8) + (hash<<40);
    }

    return hash;
}

// String hash: SDBM, 32-bit version.
static inline uint32_t hash_sdbm_32(const uint8_t* string, size_t length) {
    uint32_t hash = 0;

    // Function: hash(i) = hash(i - 1) * 65599 + string[i]
    for (size_t i = 0; i < length; i++) {
        hash = string[i] + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

// String hash: SDBM, 64-bit version.
static inline uint64_t hash_sdbm_64(const uint8_t* string, size_t length) {
    uint64_t hash = 0;

    // Function: hash(i) = hash(i - 1) * 65599 + string[i]
    for (size_t i = 0; i < length; i++) {
        hash = string[i] + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

#endif
