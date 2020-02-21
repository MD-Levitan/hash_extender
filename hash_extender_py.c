#define PY_SSIZE_T_CLEAN
#include <python3.7/Python.h>

#define MODULE_NAME "hash_extender"

#include "hash_extender_engine.h"

typedef struct short_options_t short_options_t;

struct short_options_t
{
    /* Clear text for hash */
    uint8_t *data;

    /* Length of this data */
    uint64_t data_length;

    /* Append data */
    uint8_t *append_data;

    /*  Length of append data */
    uint64_t append_length;

    /* Signature data */
    uint8_t *sign;
    
    /* Length of signature */
    uint64_t sign_length;

    /* Hash function name */
    char *hash_name;

    /* Secret length */
    uint64_t secret_length;

};


static PyObject* hash_extender(PyObject *self, PyObject *args, PyObject *keywds)
{
    short_options_t opt;
    PyObject *value;
    static char *kwlist[] = {"data", "data_len", "append", "append_len",
                             "sign", "sign_len", "hash_name", "secret_len", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sisisisi", kwlist,
                                     &opt.data, &opt.data_length,
                                     &opt.append_data, &opt.append_length,
                                     &opt.sign, &opt.sign_length,
                                     &opt.hash_name, &opt.secret_length))
    {
        fprintf(stderr, "Cannot parse args");
        return NULL;
    }
    uint8_t *new_data;
    uint8_t new_signature[MAX_DIGEST_LENGTH];
    uint64_t new_length;
    uint8_t *out_data;
    uint64_t out_length;

    /* Generate the new data. */
    new_data = hash_append_data(opt.hash_name, opt.data, opt.data_length, opt.secret_length, opt.append_data, opt.append_length, &new_length);
    /* Generate the signature for it.  */
    hash_gen_signature_evil(opt.hash_name, opt.secret_length, opt.data_length, opt.sign, opt.append_data, opt.append_length, new_signature);

    out_data = format_encode("hex", new_signature, opt.secret_length * 2, &out_length);
    free(new_data);
   
    value = Py_BuildValue("s#y#", (char *)out_data, out_length, (char *)new_data, new_length);
    free(out_data);
    /* Free the buffer. */
    return value; 
    
    // Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
    {"hash_extender_default",  hash_extender, METH_KEYWORDS | METH_VARARGS,
"hash_extender(data, data_len, append, append_len, sign, sign_len, hash_name, secret_len)\n"
"\n"
"Input:\n"
    "data(str):\tThe original string that we're going to extend.\n"
    "data_len(int):\tThe length of string with data.\n"
    "append(str):\tThe data to append to the string.\n"
    "append_len(int):\tThe length of appended string.\n"
    "sign(str):\tThe original signature in HEX.\n"
    "sign_len(str):\tThe length of signature.\n"
    "hash_name(str):\tName of hash function.\n"
    "secret_len(int):\tThe secret lengths.\n"
"Returns:\n"
"    The pair with new hex digest and new message.\n"
},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME,
    NULL,
    -1,
    methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC PyInit_hash_extender(void)
{
    return PyModule_Create(&moduledef);
}

