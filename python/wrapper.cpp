#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/operators.h>
#include "seal/batchencoder.h"
#include "seal/biguint.h"
#include "seal/defaultparams.h"
#include "seal/ciphertext.h"
#include "seal/ckks.h"
#include "seal/decryptor.h"
#include "seal/encoder.h"
#include "seal/encryptor.h"
#include "seal/encryptionparams.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/plaintext.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"

namespace py = pybind11;

using namespace pybind11::literals;
using namespace seal;
using namespace std;

template<class T>
py::tuple serialize(T &c) {
    std::stringstream output(std::ios::binary | std::ios::out);
    c.save(output);
    std::string cipherstr = output.str();
    return py::make_tuple(py::bytes(cipherstr));
}

template<class T>
T deserialize(py::tuple t) {
    if (t.size() != 1)
        throw std::runtime_error("(Pickle) Invalid input tuple!");
    T c = T();
    std::string cipherstr = t[0].cast<std::string>();
    std::stringstream input(std::ios::binary | std::ios::in);
    input.str(cipherstr);
    c.unsafe_load(input);
    return c;
}

PYBIND11_MODULE(_seal, m) {
    m.attr("__name__") = "microsoft.seal._seal";
    
    using ctx_ptr_t = std::shared_ptr<SEALContext>;

//   py::class_<BigUInt>(m, "BigUInt")
//     .def(py::init<>())
//     .def("to_double", &BigUInt::to_double,
//           "Returns the BigUInt value as a double. Note that precision may be lost during the conversion.")
//     .def("significant_bit_count", (int (BigUInt::*)()) &BigUInt::significant_bit_count, "Returns the value of the current SmallModulus");

  py::class_<SmallModulus>(m, "SmallModulus")
    .def(py::init<std::uint64_t>(),
        py::arg("value") = 0)
    .def_property_readonly("value", (std::uint64_t (SmallModulus::*)()) &SmallModulus::value, "The value of the current SmallModulus");
    
  m.def("coeff_modulus_256", &coeff_modulus_256, "Returns the default coefficients modulus for a given polynomial modulus degree.");
  m.def("coeff_modulus_192", &coeff_modulus_192, "Returns the default coefficients modulus for a given polynomial modulus degree.");
  m.def("coeff_modulus_128", &coeff_modulus_128, "Returns the default coefficients modulus for a given polynomial modulus degree.");
  m.def("small_mods_60bit", &small_mods_60bit, "Returns a 60-bit coefficient modulus prime.");
  m.def("small_mods_50bit", &small_mods_50bit, "Returns a 50-bit coefficient modulus prime.");
  m.def("small_mods_40bit", &small_mods_40bit, "Returns a 40-bit coefficient modulus prime.");
  m.def("small_mods_30bit", &small_mods_30bit, "Returns a 30-bit coefficient modulus prime.");
  m.def("dbc_max", &dbc_max, "Returns the largest allowed decomposition bit count.");
  m.def("dbc_min", &dbc_max, "Returns the smallest allowed decomposition bit count.");

  py::class_<MemoryPoolHandle>(m, "MemoryPoolHandle")
    .def(py::init<>())
    .def(py::init<const MemoryPoolHandle&>())
    .def_property_readonly("alloc_byte_count", &MemoryPoolHandle::alloc_byte_count, "Returns the size of allocated memory.")
    .def_property_readonly("pool_count", &MemoryPoolHandle::pool_count, "Returns the number of different allocation sizes.");

  py::enum_<mm_prof_opt>(m, "mm_prof_opt")
    .value("DEFAULT", mm_prof_opt::DEFAULT)
    .value("FORCE_GLOBAL", mm_prof_opt::FORCE_GLOBAL)
    .value("FORCE_NEW", mm_prof_opt::FORCE_NEW)
    .value("FORCE_THREAD_LOCAL", mm_prof_opt::FORCE_THREAD_LOCAL);
  
  m.def("get_pool", [](mm_prof_opt prof_opt) {
      return MemoryManager::GetPool(prof_opt);
  }, "Returns a MemoryPoolHandle according to the currently set memory manager profile and prof_opt.");
  m.def("get_pool", (MemoryPoolHandle (*)())(&MemoryManager::GetPool), "Returns a MemoryPoolHandle according to the currently set memory manager profile.");

  py::class_<Plaintext>(m, "Plaintext")
    .def(py::init<>())
    .def(py::init<MemoryPoolHandle>())
    .def(py::init<Plaintext::size_type>())
    .def(py::init<Plaintext::size_type, MemoryPoolHandle>())
    .def(py::init<Plaintext::size_type, Plaintext::size_type>())
    .def(py::init<Plaintext::size_type, Plaintext::size_type, MemoryPoolHandle>())
    .def(py::init<const std::string&>())
    .def(py::init<const std::string&, MemoryPoolHandle>())
    .def(py::pickle(&serialize<Plaintext>, &deserialize<Plaintext>))
    .def_property_readonly("is_ntt_form", [](Plaintext &p) { return p.is_ntt_form(); },
        "Whether the plaintext is in NTT form")
    .def_property_readonly("is_zero", [](Plaintext &p) { return p.is_zero(); },
        "Returns whether the current plaintext polynomial has all zero coefficients.")
    .def_property_readonly("parms_id", (parms_id_type& (Plaintext::*)()) &Plaintext::parms_id,
        "The parms_id")
    .def_property("scale", (double& (Plaintext::*)()) &Plaintext::scale,
        [](Plaintext &p, double scale) { p.scale() = scale; },
        "The scale")
    .def_property_readonly("pool", &Plaintext::pool,
        "The currently used MemoryPoolHandle")
    .def(py::self == py::self)
    .def(py::self != py::self)
    .def("__repr__", &Plaintext::to_string);

  py::class_<Ciphertext>(m, "Ciphertext")
    .def(py::init<>())
    .def(py::init<MemoryPoolHandle>())
    .def(py::init<ctx_ptr_t>())
    .def(py::init<ctx_ptr_t, MemoryPoolHandle>())
    .def(py::init<ctx_ptr_t, parms_id_type>())
    .def(py::init<ctx_ptr_t, parms_id_type, MemoryPoolHandle>())
    .def(py::init<ctx_ptr_t, parms_id_type, Ciphertext::size_type>())
    .def(py::init<ctx_ptr_t, parms_id_type, Ciphertext::size_type, MemoryPoolHandle>())
    .def(py::init<const Ciphertext &>())
    .def("reserve", (void (Ciphertext::*)(ctx_ptr_t, parms_id_type, Ciphertext::size_type)) &Ciphertext::reserve,
        "Allocates enough memory to accommodate the backing array of a ciphertext with given capacity")
    .def("reserve", (void (Ciphertext::*)(ctx_ptr_t, Ciphertext::size_type)) &Ciphertext::reserve,
        "Allocates enough memory to accommodate the backing array of a ciphertext with given capacity")
    .def("reserve", (void (Ciphertext::*)(Ciphertext::size_type)) &Ciphertext::reserve,
        "Allocates enough memory to accommodate the backing array of a ciphertext with given capacity")
    .def_property_readonly("coeff_mod_count", &Ciphertext::coeff_mod_count,
        "The number of primes in the coefficient modulus of the associated encryption parameters")
    .def_property_readonly("poly_modulus_degree", &Ciphertext::poly_modulus_degree,
        "The degree of the polynomial modulus of the associated encryption parameters")
    .def_property_readonly("size_capacity", &Ciphertext::size_capacity,
        "The capacity of the allocation")
    .def_property_readonly("size", &Ciphertext::size,
        "The size of the ciphertext")
    .def(py::pickle(&serialize<Ciphertext>, &deserialize<Ciphertext>))
    .def_property_readonly("is_ntt_form", [](Ciphertext &c) { return c.is_ntt_form(); },
        "Whether the ciphertext is in NTT form")
    .def_property_readonly("parms_id", (parms_id_type& (Ciphertext::*)()) &Ciphertext::parms_id,
        "The parms_id")
    .def_property("scale", (double& (Ciphertext::*)()) &Ciphertext::scale,
        [](Ciphertext &c, double scale) { c.scale() = scale; },
        "The scale")
    .def_property_readonly("pool", &Ciphertext::pool,
        "The currently used MemoryPoolHandle");

  py::enum_<scheme_type>(m, "scheme_type")
    .value("BFV", scheme_type::BFV)
    .value("CKKS", scheme_type::CKKS);

  py::class_<EncryptionParameters>(m, "EncryptionParameters")
    .def(py::init<scheme_type>())
    .def(py::init<const EncryptionParameters &>())
    .def_property("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree, &EncryptionParameters::set_poly_modulus_degree,
        "The degree of the polynomial modulus parameter")
    .def_property("coeff_modulus", &EncryptionParameters::coeff_modulus, &EncryptionParameters::set_coeff_modulus,
        "The coefficient modulus parameter")
    .def_property("plain_modulus", &EncryptionParameters::plain_modulus,
        [](EncryptionParameters &p, py::object arg) {
            try {
                p.set_plain_modulus(arg.cast<const SmallModulus &>());
                return;
            } catch (py::cast_error) {}
            try {
                p.set_plain_modulus(arg.cast<std::uint64_t>());
                return;
            } catch (py::cast_error) {}
            throw std::invalid_argument("No appropriate overload for set_plain_modulus");
        },
        "The plaintext modulus parameter")
    .def_property("noise_standard_deviation", &EncryptionParameters::noise_standard_deviation, (void (EncryptionParameters::*)(double)) &EncryptionParameters::set_noise_standard_deviation,
        "The standard deviation of the noise distribution used for error sampling")
    .def_property_readonly("scheme", &EncryptionParameters::scheme,
        "The encryption scheme type")
    .def_property_readonly("parms_id", &EncryptionParameters::parms_id,
        "The parms_id of the current parameters");

  py::class_<EncryptionParameterQualifiers>(m, "EncryptionParameterQualifiers")
    .def_readonly("parameters_set", &EncryptionParameterQualifiers::parameters_set)
    .def_readonly("using_fft", &EncryptionParameterQualifiers::using_fft)
    .def_readonly("using_ntt", &EncryptionParameterQualifiers::using_ntt)
    .def_readonly("using_batching", &EncryptionParameterQualifiers::using_batching)
    .def_readonly("using_fast_plain_lift", &EncryptionParameterQualifiers::using_fast_plain_lift)
    .def_readonly("using_he_std_security", &EncryptionParameterQualifiers::using_he_std_security);

  py::class_<SEALContext::ContextData, std::shared_ptr<SEALContext::ContextData>>(m, "ContextData")
    .def_property_readonly("parms", &SEALContext::ContextData::parms,
        "The underlying encryption parameters")
    .def_property_readonly("qualifiers", &SEALContext::ContextData::qualifiers,
        "EncryptionParameterQualifiers corresponding to the current encryption parameters")
    .def_property_readonly("total_coeff_modulus_bit_count", &SEALContext::ContextData::total_coeff_modulus_bit_count,
        "The significant bit count of the total coefficient modulus")
    .def_property_readonly("next_context_data", &SEALContext::ContextData::next_context_data,
        "The context data corresponding to the next parameters in the modulus switching chain")
    .def_property_readonly("chain_index", &SEALContext::ContextData::chain_index,
        "The index of the parameter set in a chain");

  py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
    .def_static("Create", &SEALContext::Create,
        py::arg("parms"), py::arg("expand_mod_chain") = true,
        "Creates an instance of SEALContext, and performs several pre-computations on the given EncryptionParameters")
    .def("context_data", (std::shared_ptr<const SEALContext::ContextData> (SEALContext::*)() const) &SEALContext::context_data,
        "Returns the ContextData corresponding to the encryption parameters. This is the first set of parameters in a chain of parameters when modulus switching is used.")
    .def("context_data", (std::shared_ptr<const SEALContext::ContextData> (SEALContext::*)(parms_id_type) const) &SEALContext::context_data,
        "Returns the ContextData corresponding to the parameters with a given parms_id.");

  py::class_<PublicKey>(m, "PublicKey")
    .def(py::init<>())
    .def(py::pickle(&serialize<PublicKey>, &deserialize<PublicKey>))
    .def_property_readonly("parms_id", (parms_id_type& (PublicKey::*)()) &PublicKey::parms_id,
        "The parms_id")
    .def_property_readonly("pool", &PublicKey::pool,
        "The currently used MemoryPoolHandle");

  py::class_<SecretKey>(m, "SecretKey")
    .def(py::init<>())
    .def(py::pickle(&serialize<SecretKey>, &deserialize<SecretKey>))
    .def_property_readonly("parms_id", (parms_id_type& (SecretKey::*)()) &SecretKey::parms_id,
        "The parms_id")
    .def_property_readonly("pool", &SecretKey::pool,
        "The currently used MemoryPoolHandle");
    
  py::class_<RelinKeys>(m, "RelinKeys")
    .def(py::init<>())
    .def(py::init<const RelinKeys&>())
    .def_property_readonly("size", &RelinKeys::size,
        "The current number of relinearization keys")
    .def_property_readonly("decomposition_bit_count", &RelinKeys::decomposition_bit_count,
        "The decomposition bit count")
    .def("has_key", &RelinKeys::has_key,
        "Returns whether an relinearization key corresponding to a given power of the secret key exists")
    .def_property_readonly("parms_id", (parms_id_type& (RelinKeys::*)()) &RelinKeys::parms_id,
        "The parms_id")
    .def(py::pickle(&serialize<RelinKeys>, &deserialize<RelinKeys>))
    .def_property_readonly("pool", &RelinKeys::pool,
        "The currently used MemoryPoolHandle");

  py::class_<GaloisKeys>(m, "GaloisKeys")
    .def(py::init<>())
    .def(py::init<const GaloisKeys&>())
    .def_property_readonly("size", &GaloisKeys::size,
        "The current number of Galois keys")
    .def_property_readonly("decomposition_bit_count", &GaloisKeys::decomposition_bit_count,
        "The decomposition bit count")
    .def("has_key", &GaloisKeys::has_key,
        "Returns whether a Galois key corresponding to a given Galois element exists")
    .def_property_readonly("parms_id", (parms_id_type& (GaloisKeys::*)()) &GaloisKeys::parms_id,
        "The parms_id")
    .def(py::pickle(&serialize<GaloisKeys>, &deserialize<GaloisKeys>))
    .def_property_readonly("pool", &GaloisKeys::pool,
        "The currently used MemoryPoolHandle");

  py::class_<KeyGenerator>(m, "KeyGenerator")
    .def(py::init<ctx_ptr_t>())
    .def(py::init<ctx_ptr_t, const SecretKey &, const PublicKey &>())
    .def("relin_keys", (RelinKeys (KeyGenerator::*)(int, std::size_t)) &KeyGenerator::relin_keys,
        py::arg("decomposition_bit_count"), py::arg("count") = 1,
        "Generates and returns the specified number of relinearization keys")
    .def("galois_keys", (GaloisKeys (KeyGenerator::*)(int)) &KeyGenerator::galois_keys,
        "Generates and returns Galois keys")
    // .def("galois_keys", (GaloisKeys (KeyGenerator::*)(int, const std::vector<std::uint64_t>&)) &KeyGenerator::galois_keys,
    //     "Generates and returns Galois keys")
    .def("galois_keys", (GaloisKeys (KeyGenerator::*)(int, const std::vector<int>&)) &KeyGenerator::galois_keys,
        "Generates and returns Galois keys")
    .def_property_readonly("public_key", &KeyGenerator::public_key, "The public key")
    .def_property_readonly("secret_key", &KeyGenerator::secret_key, "The secret key");

  py::class_<Encryptor>(m, "Encryptor")
    .def(py::init<ctx_ptr_t, const PublicKey &>())
    .def("encrypt", [](Encryptor &e, const Plaintext &plain, Ciphertext &destination) { e.encrypt(plain, destination); },
        "Encrypts a Plaintext and stores the result in the destination parameter")
    .def("encrypt", (void (Encryptor::*)(const Plaintext &, Ciphertext &, MemoryPoolHandle)) &Encryptor::encrypt,
        py::arg("plain"), py::arg("destination"), py::arg("pool"),
        "Encrypts a Plaintext and stores the result in the destination parameter");

  py::class_<Decryptor>(m, "Decryptor")
    .def(py::init<ctx_ptr_t, const SecretKey &>())
    .def("decrypt", (void (Decryptor::*)(const Ciphertext &, Plaintext &)) &Decryptor::decrypt,
        "Decrypts a Ciphertext and stores the result in the destination parameter")
    .def("invariant_noise_budget", (int (Decryptor::*)(const Ciphertext &)) &Decryptor::invariant_noise_budget,
        "Computes the invariant noise budget (in bits) of a ciphertext");

  py::class_<Evaluator>(m, "Evaluator")
    .def(py::init<ctx_ptr_t>())
    .def("negate_inplace", (void (Evaluator::*)(Ciphertext&)) &Evaluator::negate_inplace,
        "Negates a ciphertext")
    .def("negate", (void (Evaluator::*)(const Ciphertext&, Ciphertext&)) &Evaluator::negate,
        "Negates a ciphertext")
    .def("add_inplace", (void (Evaluator::*)(Ciphertext&, const Ciphertext&)) &Evaluator::add_inplace,
        "Adds two ciphertexts")
    .def("add", (void (Evaluator::*)(const Ciphertext&, const Ciphertext&, Ciphertext&)) &Evaluator::add,
        "Adds two ciphertexts")
    .def("add_many", (void (Evaluator::*)(const std::vector<Ciphertext>&, Ciphertext&)) &Evaluator::add_many,
        "Adds together a vector of ciphertexts")
    .def("sub_inplace", (void (Evaluator::*)(Ciphertext&, const Ciphertext&)) &Evaluator::sub_inplace,
        "Subtracts two ciphertexts")
    .def("sub", (void (Evaluator::*)(const Ciphertext&, const Ciphertext&, Ciphertext&)) &Evaluator::sub,
        "Subtracts two ciphertexts")

    .def("multiply_inplace", [](Evaluator &e, Ciphertext &encrypted1, const Ciphertext& encrypted2) { e.multiply_inplace(encrypted1, encrypted2); },
        "Multiplies two ciphertexts")
    .def("multiply_inplace", (void (Evaluator::*)(Ciphertext&, const Ciphertext&, MemoryPoolHandle)) &Evaluator::multiply_inplace,
        py::arg("encrypted1"), py::arg("encrypted2"), py::arg("pool"),
        "Multiplies two ciphertexts")

    .def("multiply", [](Evaluator &e, const Ciphertext &encrypted1, const Ciphertext &encrypted2, Ciphertext &destination) { e.multiply(encrypted1, encrypted2, destination); },
        "Multiplies two ciphertexts")
    .def("multiply", (void (Evaluator::*)(const Ciphertext&, const Ciphertext&, Ciphertext&, MemoryPoolHandle)) &Evaluator::multiply,
        py::arg("encrypted1"), py::arg("encrypted2"), py::arg("destination"), py::arg("pool"),
        "Multiplies two ciphertexts")

    .def("square_inplace", [](Evaluator &e, Ciphertext &encrypted) { e.square_inplace(encrypted); },
        "Squares a ciphertext")
    .def("square_inplace", (void (Evaluator::*)(Ciphertext&, MemoryPoolHandle)) &Evaluator::square_inplace,
        py::arg("encrypted"), py::arg("pool"),
        "Squares a ciphertext")

    .def("square", [](Evaluator &e, const Ciphertext &encrypted, Ciphertext &destination) { e.square(encrypted, destination); },
        "Squares a ciphertext")
    .def("square", (void (Evaluator::*)(const Ciphertext&, Ciphertext&, MemoryPoolHandle)) &Evaluator::square,
        py::arg("encrypted"), py::arg("destination"), py::arg("pool"),
        "Squares a ciphertext")

    .def("relinearize_inplace", [](Evaluator &e, Ciphertext &encrypted, const RelinKeys &relin_keys) { e.relinearize_inplace(encrypted, relin_keys); },
        "Relinearizes a ciphertext")
    .def("relinearize_inplace", (void (Evaluator::*)(Ciphertext&, const RelinKeys&, MemoryPoolHandle)) &Evaluator::relinearize_inplace,
        py::arg("encrypted"), py::arg("relin_keys"), py::arg("pool"),
        "Relinearizes a ciphertext")

    .def("relinearize", [](Evaluator &e, const Ciphertext &encrypted, const RelinKeys &relin_keys, Ciphertext &destination) { e.relinearize(encrypted, relin_keys, destination); },
        "Relinearizes a ciphertext")
    .def("relinearize", (void (Evaluator::*)(const Ciphertext&, const RelinKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::relinearize,
        py::arg("encrypted"), py::arg("relin_keys"), py::arg("destination"), py::arg("pool"),
        "Relinearizes a ciphertext")

    .def("mod_switch_to_next", [](Evaluator &e, const Ciphertext &encrypted, Ciphertext &destination) { e.mod_switch_to_next(encrypted, destination); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}")
    .def("mod_switch_to_next", (void (Evaluator::*)(const Ciphertext&, Ciphertext&, MemoryPoolHandle)) &Evaluator::mod_switch_to_next,
        py::arg("encrypted"), py::arg("destination"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}")

    .def("mod_switch_to_next_inplace", [](Evaluator &e, Ciphertext &encrypted) { e.mod_switch_to_next_inplace(encrypted); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}")
    .def("mod_switch_to_next_inplace", (void (Evaluator::*)(Ciphertext&, MemoryPoolHandle)) &Evaluator::mod_switch_to_next_inplace,
        py::arg("encrypted"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}")

    .def("mod_switch_to_next_inplace", (void (Evaluator::*)(Plaintext&)) &Evaluator::mod_switch_to_next_inplace,
        "Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo q_1...q_{k-1}")
    .def("mod_switch_to_next", (void (Evaluator::*)(const Plaintext&, Plaintext&)) &Evaluator::mod_switch_to_next,
        "Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo q_1...q_{k-1}")

    .def("mod_switch_to_inplace", [](Evaluator &e, Ciphertext &encrypted, parms_id_type parms_id) { e.mod_switch_to_inplace(encrypted, parms_id); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id")
    .def("mod_switch_to_inplace", (void (Evaluator::*)(Ciphertext&, parms_id_type, MemoryPoolHandle)) &Evaluator::mod_switch_to_inplace,
        py::arg("encrypted"), py::arg("parms_id"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id")

    .def("mod_switch_to", [](Evaluator &e, const Ciphertext &encrypted, parms_id_type parms_id, Ciphertext &destination) { e.mod_switch_to(encrypted, parms_id, destination); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id")
    .def("mod_switch_to", (void (Evaluator::*)(const Ciphertext&, parms_id_type, Ciphertext&, MemoryPoolHandle)) &Evaluator::mod_switch_to,
        py::arg("encrypted"), py::arg("parms_id"), py::arg("destination"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id")

    .def("mod_switch_to_inplace", (void (Evaluator::*)(Plaintext&, parms_id_type)) &Evaluator::mod_switch_to_inplace,
        "Given an NTT transformed plaintext modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id")
    .def("mod_switch_to", (void (Evaluator::*)(const Plaintext&, parms_id_type, Plaintext&)) &Evaluator::mod_switch_to,
        "Given an NTT transformed plaintext modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id")

    .def("rescale_to_next", [](Evaluator &e, const Ciphertext &encrypted, Ciphertext &destination) { e.rescale_to_next(encrypted, destination); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}, scales the message down accordingly,")
    .def("rescale_to_next", (void (Evaluator::*)(const Ciphertext&, Ciphertext&, MemoryPoolHandle)) &Evaluator::rescale_to_next,
        py::arg("encrypted"), py::arg("destination"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1}, scales the message down accordingly,")

    .def("rescale_to_next_inplace", [](Evaluator &e, Ciphertext &encrypted) { e.rescale_to_next_inplace(encrypted); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1} and scales the message down accordingly")
    .def("rescale_to_next_inplace", (void (Evaluator::*)(Ciphertext&, MemoryPoolHandle)) &Evaluator::rescale_to_next_inplace,
        py::arg("encrypted"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1} and scales the message down accordingly")

    .def("rescale_to_inplace", [](Evaluator &e, Ciphertext &encrypted, parms_id_type parms_id) { e.rescale_to_inplace(encrypted, parms_id); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id and scales the message down accordingly")
    .def("rescale_to_inplace", (void (Evaluator::*)(Ciphertext&, parms_id_type, MemoryPoolHandle)) &Evaluator::rescale_to_inplace,
        py::arg("encrypted"), py::arg("parms_id"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id and scales the message down accordingly")

    .def("rescale_to", [](Evaluator &e, const Ciphertext &encrypted, parms_id_type parms_id, Ciphertext &destination) { e.rescale_to(encrypted, parms_id, destination); },
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id, scales the message down accordingly,")
    .def("rescale_to", (void (Evaluator::*)(const Ciphertext&, parms_id_type, Ciphertext&, MemoryPoolHandle)) &Evaluator::rescale_to,
        py::arg("encrypted"), py::arg("parms_id"), py::arg("destination"), py::arg("pool"),
        "Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down until the parameters reach the given parms_id, scales the message down accordingly,")

    .def("multiply_many", [](Evaluator &e, std::vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys, Ciphertext &destination) { e.multiply_many(encrypteds, relin_keys, destination); },
        "Multiplies together a vector of ciphertexts")
    .def("multiply_many", (void (Evaluator::*)(std::vector<Ciphertext>&, const RelinKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::multiply_many,
        py::arg("encrypteds"), py::arg("relin_keys"), py::arg("destination"), py::arg("pool"),
        "Multiplies together a vector of ciphertexts")

    .def("exponentiate_inplace", [](Evaluator &e, Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys) { e.exponentiate_inplace(encrypted, exponent, relin_keys); },
        "Exponentiates a ciphertext")
    .def("exponentiate_inplace", (void (Evaluator::*)(Ciphertext&, std::uint64_t, const RelinKeys&, MemoryPoolHandle)) &Evaluator::exponentiate_inplace,
        py::arg("encrypted"), py::arg("exponent"), py::arg("relin_keys"), py::arg("pool"),
        "Exponentiates a ciphertext")

    .def("exponentiate", [](Evaluator &e, const Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys, Ciphertext &destination) { e.exponentiate(encrypted, exponent, relin_keys, destination); },
        "Exponentiates a ciphertext")
    .def("exponentiate", (void (Evaluator::*)(const Ciphertext&, std::uint64_t, const RelinKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::exponentiate,
        py::arg("encrypted"), py::arg("exponent"), py::arg("relin_keys"), py::arg("destination"), py::arg("pool"),
        "Exponentiates a ciphertext")

    .def("add_plain_inplace", (void (Evaluator::*)(Ciphertext&, const Plaintext&)) &Evaluator::add_plain_inplace,
        "Adds a ciphertext and a plaintext")
    .def("add_plain", (void (Evaluator::*)(const Ciphertext&, const Plaintext&, Ciphertext&)) &Evaluator::add_plain,
        "Adds a ciphertext and a plaintext")
    .def("sub_plain_inplace", (void (Evaluator::*)(Ciphertext&, const Plaintext&)) &Evaluator::sub_plain_inplace,
        "Subtracts a plaintext from a ciphertext")
    .def("sub_plain", (void (Evaluator::*)(const Ciphertext&, const Plaintext&, Ciphertext&)) &Evaluator::sub_plain,
        "Subtracts a plaintext from a ciphertext")

    .def("multiply_plain_inplace", [](Evaluator &e, Ciphertext &encrypted, const Plaintext &plain) { e.multiply_plain_inplace(encrypted, plain); },
        "Multiplies a ciphertext with a plaintext")
    .def("multiply_plain_inplace", (void (Evaluator::*)(Ciphertext&, const Plaintext&, MemoryPoolHandle)) &Evaluator::multiply_plain_inplace,
        py::arg("encrypted"), py::arg("plain"), py::arg("pool"),
        "Multiplies a ciphertext with a plaintext")

    .def("multiply_plain", [](Evaluator &e, const Ciphertext &encrypted, const Plaintext &plain, Ciphertext &destination) { e.multiply_plain(encrypted, plain, destination); },
        "Multiplies a ciphertext with a plaintext")
    .def("multiply_plain", (void (Evaluator::*)(const Ciphertext&, const Plaintext&, Ciphertext&, MemoryPoolHandle)) &Evaluator::multiply_plain,
        py::arg("encrypted"), py::arg("plain"), py::arg("destination"), py::arg("pool"),
        "Multiplies a ciphertext with a plaintext")

    .def("transform_to_ntt_inplace", [](Evaluator &e, Plaintext &plain, parms_id_type parms_id) { e.transform_to_ntt_inplace(plain, parms_id); },
        "Transforms a plaintext to NTT domain")
    .def("transform_to_ntt_inplace", (void (Evaluator::*)(Plaintext&, parms_id_type, MemoryPoolHandle)) &Evaluator::transform_to_ntt_inplace,
        py::arg("plain"), py::arg("parms_id"), py::arg("pool"),
        "Transforms a plaintext to NTT domain")

    .def("transform_to_ntt", [](Evaluator &e, const Plaintext &plain, parms_id_type parms_id, Plaintext &destination_ntt) { e.transform_to_ntt(plain, parms_id, destination_ntt); },
        "Transforms a plaintext to NTT domain")
    .def("transform_to_ntt", (void (Evaluator::*)(const Plaintext&, parms_id_type, Plaintext&, MemoryPoolHandle)) &Evaluator::transform_to_ntt,
        py::arg("plain"), py::arg("parms_id"), py::arg("destination_ntt"), py::arg("pool"),
        "Transforms a plaintext to NTT domain")

    .def("transform_to_ntt_inplace", (void (Evaluator::*)(Ciphertext&)) &Evaluator::transform_to_ntt_inplace,
        "Transforms a ciphertext to NTT domain")
    .def("transform_to_ntt", (void (Evaluator::*)(const Ciphertext&, Ciphertext&)) &Evaluator::transform_to_ntt,
        "Transforms a ciphertext to NTT domain")
    .def("transform_from_ntt_inplace", (void (Evaluator::*)(Ciphertext&)) &Evaluator::transform_from_ntt_inplace,
        "Transforms a ciphertext back from NTT domain")
    .def("transform_from_ntt", (void (Evaluator::*)(const Ciphertext&, Ciphertext&)) &Evaluator::transform_from_ntt,
        "Transforms a ciphertext back from NTT domain")

    .def("apply_galois_inplace", [](Evaluator &e, Ciphertext &encrypted, std::uint64_t galois_elt, const GaloisKeys &galois_keys) { e.apply_galois_inplace(encrypted, galois_elt, galois_keys); },
        "Applies a Galois automorphism to a ciphertext")
    .def("apply_galois_inplace", (void (Evaluator::*)(Ciphertext&, std::uint64_t, const GaloisKeys&, MemoryPoolHandle)) &Evaluator::apply_galois_inplace,
        py::arg("encrypted"), py::arg("galois_elt"), py::arg("galois_keys"), py::arg("pool"),
        "Applies a Galois automorphism to a ciphertext")

    .def("apply_galois", [](Evaluator &e, const Ciphertext &encrypted, std::uint64_t galois_elt, const GaloisKeys &galois_keys, Ciphertext &destination) { e.apply_galois(encrypted, galois_elt, galois_keys, destination); },
        "Applies a Galois automorphism to a ciphertext")
    .def("apply_galois", (void (Evaluator::*)(const Ciphertext&, std::uint64_t, const GaloisKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::apply_galois,
        py::arg("encrypted"), py::arg("galois_elt"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool"),
        "Applies a Galois automorphism to a ciphertext")

    .def("rotate_rows_inplace", [](Evaluator &e, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys) { e.rotate_rows_inplace(encrypted, steps, galois_keys); },
        "Rotates plaintext matrix rows cyclically")
    .def("rotate_rows_inplace", (void (Evaluator::*)(Ciphertext&, int, const GaloisKeys&, MemoryPoolHandle)) &Evaluator::rotate_rows_inplace,
        py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("pool"),
        "Rotates plaintext matrix rows cyclically")

    .def("rotate_rows", [](Evaluator &e, const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, Ciphertext &destination) { e.rotate_rows(encrypted, steps, galois_keys, destination); },
        "Rotates plaintext matrix rows cyclically")
    .def("rotate_rows", (void (Evaluator::*)(const Ciphertext&, int, const GaloisKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::rotate_rows,
        py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool"),
        "Rotates plaintext matrix rows cyclically")

    .def("rotate_columns_inplace", [](Evaluator &e, Ciphertext &encrypted, const GaloisKeys &galois_keys) { e.rotate_columns_inplace(encrypted, galois_keys); },
        "Rotates plaintext matrix columns cyclically")
    .def("rotate_columns_inplace", (void (Evaluator::*)(Ciphertext&, const GaloisKeys&, MemoryPoolHandle)) &Evaluator::rotate_columns_inplace,
        py::arg("encrypted"), py::arg("galois_keys"), py::arg("pool"),
        "Rotates plaintext matrix columns cyclically")

    .def("rotate_columns", [](Evaluator &e, const Ciphertext &encrypted, const GaloisKeys &galois_keys, Ciphertext &destination) { e.rotate_columns(encrypted, galois_keys, destination); },
        "Rotates plaintext matrix columns cyclically")
    .def("rotate_columns", (void (Evaluator::*)(const Ciphertext&, const GaloisKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::rotate_columns,
        py::arg("encrypted"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool"),
        "Rotates plaintext matrix columns cyclically")

    .def("rotate_vector_inplace", [](Evaluator &e, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys) { e.rotate_vector_inplace(encrypted, steps, galois_keys); },
        "Rotates plaintext vector cyclically")
    .def("rotate_vector_inplace", (void (Evaluator::*)(Ciphertext&, int, const GaloisKeys&, MemoryPoolHandle)) &Evaluator::rotate_vector_inplace,
        py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("pool"),
        "Rotates plaintext vector cyclically")

    .def("rotate_vector", [](Evaluator &e, const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, Ciphertext &destination) { e.rotate_vector(encrypted, steps, galois_keys, destination); },
        "Rotates plaintext vector cyclically")
    .def("rotate_vector", (void (Evaluator::*)(const Ciphertext&, int, const GaloisKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::rotate_vector,
        py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool"),
        "Rotates plaintext vector cyclically")

    .def("complex_conjugate_inplace", [](Evaluator &e, Ciphertext &encrypted, const GaloisKeys &galois_keys) { e.complex_conjugate_inplace(encrypted, galois_keys); },
        "Complex conjugates plaintext slot values")
    .def("complex_conjugate_inplace", (void (Evaluator::*)(Ciphertext&, const GaloisKeys&, MemoryPoolHandle)) &Evaluator::complex_conjugate_inplace,
        py::arg("encrypted"), py::arg("galois_keys"), py::arg("pool"),
        "Complex conjugates plaintext slot values")

    .def("complex_conjugate", [](Evaluator &e, const Ciphertext &encrypted, const GaloisKeys &galois_keys, Ciphertext &destination) { e.complex_conjugate(encrypted, galois_keys, destination); },
        "Complex conjugates plaintext slot values")
    .def("complex_conjugate", (void (Evaluator::*)(const Ciphertext&, const GaloisKeys&, Ciphertext&, MemoryPoolHandle)) &Evaluator::complex_conjugate,
        py::arg("encrypted"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool"),
        "Complex conjugates plaintext slot values");

  py::class_<CKKSEncoder>(m, "CKKSEncoder")
    .def(py::init<ctx_ptr_t>())

    .def("encode", [](CKKSEncoder &e, const std::vector<double>& values, parms_id_type parms_id, double scale, Plaintext &destination) { e.encode(values, parms_id, scale, destination); },
        "Encodes double-precision floating-point numbers into a plaintext polynomial.")
    .def("encode", (void (CKKSEncoder::*)(const std::vector<double>&, parms_id_type, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("values"), py::arg("parms_id"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes double-precision floating-point numbers into a plaintext polynomial.")

    .def("encode", [](CKKSEncoder &e, const std::vector<double>& values, double scale, Plaintext &destination) { e.encode(values, scale, destination); },
        "Encodes double-precision floating-point numbers into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")
    .def("encode", (void (CKKSEncoder::*)(const std::vector<double>&, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("values"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes double-precision floating-point numbers into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")

    .def("encode", [](CKKSEncoder &e, double value, parms_id_type parms_id, double scale, Plaintext &destination) { e.encode(value, parms_id, scale, destination); },
        "Encodes a double-precision floating-point number into a plaintext polynomial.")
    .def("encode", (void (CKKSEncoder::*)(double, parms_id_type, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("value"), py::arg("parms_id"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes a double-precision floating-point number into a plaintext polynomial.")

    .def("encode", [](CKKSEncoder &e, double value, double scale, Plaintext &destination) { e.encode(value, scale, destination); },
        "Encodes a double-precision floating-point number into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")
    .def("encode", (void (CKKSEncoder::*)(double, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("value"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes a double-precision floating-point number into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")


    .def("encode", [](CKKSEncoder &e, const std::vector<std::complex<double>>& values, parms_id_type parms_id, double scale, Plaintext &destination) { e.encode(values, parms_id, scale, destination); },
        "Encodes double-precision complex numbers into a plaintext polynomial.")
    .def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>>&, parms_id_type, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("values"), py::arg("parms_id"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes double-precision complex numbers into a plaintext polynomial.")

    .def("encode", [](CKKSEncoder &e, const std::vector<std::complex<double>>& values, double scale, Plaintext &destination) { e.encode(values, scale, destination); },
        "Encodes double-precision complex numbers into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")
    .def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>>&, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("values"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes double-precision complex numbers into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")

    .def("encode", [](CKKSEncoder &e, std::complex<double> value, parms_id_type parms_id, double scale, Plaintext &destination) { e.encode(value, parms_id, scale, destination); },
        "Encodes a double-precision complex number into a plaintext polynomial.")
    .def("encode", (void (CKKSEncoder::*)(std::complex<double>, parms_id_type, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("value"), py::arg("parms_id"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes a double-precision complex number into a plaintext polynomial.")

    .def("encode", [](CKKSEncoder &e, std::complex<double> value, double scale, Plaintext &destination) { e.encode(value, scale, destination); },
        "Encodes a double-precision complex number into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")
    .def("encode", (void (CKKSEncoder::*)(std::complex<double>, double, Plaintext&, MemoryPoolHandle)) &CKKSEncoder::encode,
        py::arg("value"), py::arg("scale"), py::arg("destination"), py::arg("pool"),
        "Encodes a double-precision complex number into a plaintext polynomial. The encryption parameters used are the top level parameters for the given context.")

    .def("encode", (void (CKKSEncoder::*)(std::int64_t, parms_id_type, Plaintext&)) &CKKSEncoder::encode,
        "Encodes an integer number into a plaintext polynomial without any scaling.")
    .def("encode", (void (CKKSEncoder::*)(std::int64_t, Plaintext&)) &CKKSEncoder::encode,
        "Encodes an integer number into a plaintext polynomial without any scaling. The encryption parameters used are the top level parameters for the given context.")

    .def("decode", [](CKKSEncoder &ckks, const Plaintext &plain) {
            std::vector<double> destination;
            ckks.decode(plain, destination);
            return destination;
        },
        "Decodes a plaintext polynomial into double-precision floating-point numbers.")
    .def("decode", [](CKKSEncoder &ckks, const Plaintext &plain, MemoryPoolHandle pool) {
            std::vector<double> destination;
            ckks.decode(plain, destination, pool);
            return destination;
        },
        py::arg("plain"), py::arg("pool"),
        "Decodes a plaintext polynomial into double-precision floating-point numbers.")
    .def_property_readonly("slot_count", &CKKSEncoder::slot_count, "The number of complex numbers encoded.");
    
  py::class_<IntegerEncoder>(m, "IntegerEncoder")
    .def(py::init<const SmallModulus&, std::uint64_t>(),
        py::arg("plain_modulus"), py::arg("base") = 2)
    .def(py::init<const IntegerEncoder &>())
    .def("encode", (Plaintext (IntegerEncoder::*)(std::uint64_t)) &IntegerEncoder::encode, "Encode integer")
    .def("encode", (void (IntegerEncoder::*)(std::uint64_t, Plaintext &)) &IntegerEncoder::encode, "Encode integer and store in given destination")
    .def("encode", (Plaintext (IntegerEncoder::*)(std::int64_t)) &IntegerEncoder::encode, "Encode integer")
    .def("encode", (void (IntegerEncoder::*)(std::int64_t, Plaintext &)) &IntegerEncoder::encode, "Encode integer and store in given destination")
    .def("encode", (Plaintext (IntegerEncoder::*)(const BigUInt &)) &IntegerEncoder::encode, "Encode integer")
    .def("encode", (void (IntegerEncoder::*)(const BigUInt &, Plaintext &)) &IntegerEncoder::encode, "Encode integer and store in given destination")
    .def("encode", (Plaintext (IntegerEncoder::*)(std::int32_t)) &IntegerEncoder::encode, "Encode integer")
    .def("encode", (Plaintext (IntegerEncoder::*)(std::uint32_t)) &IntegerEncoder::encode, "Encode integer")
    .def("encode", (void (IntegerEncoder::*)(std::int32_t, Plaintext &)) &IntegerEncoder::encode, "Encode integer and store in given destination")
    .def("encode", (void (IntegerEncoder::*)(std::uint32_t, Plaintext &)) &IntegerEncoder::encode, "Encode integer and store in given destination")
    .def("decode_biguint", (void (IntegerEncoder::*)(const Plaintext &, BigUInt &)) &IntegerEncoder::decode_biguint, "Decode a plaintext polynomial and store in a given destination")
    .def("decode_biguint", (BigUInt (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_biguint, "Decode a plaintext polynomial")
    .def("decode_int64", (std::int64_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_int64, "Decode a plaintext polynomial")
    .def("decode_int32", (std::int32_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_int32, "Decode a plaintext polynomial")
    .def("decode_uint64", (std::uint64_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_uint64, "Decode a plaintext polynomial")
    .def("decode_uint32", (std::uint32_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_uint32, "Decode a plaintext polynomial");

  py::class_<FractionalEncoder>(m, "FractionalEncoder")
    .def(py::init<const SmallModulus &, std::size_t, std::size_t, std::size_t, std::uint64_t>(),
        py::arg("plain_modulus"), py::arg("poly_modulus_degree"), py::arg("integer_coeff_count"), py::arg("fraction_coeff_count"), py::arg("base") = 2)
    .def(py::init<const FractionalEncoder &>())
    .def("encode", (Plaintext (FractionalEncoder::*)(double)) &FractionalEncoder::encode,
        "Encodes a double precision floating point number into a plaintext polynomial")
    .def("decode", (double (FractionalEncoder::*)(const Plaintext &)) &FractionalEncoder::decode,
        "Decodes a plaintext polynomial and returns the result as a double-precision floating-point number");

  py::class_<BatchEncoder>(m, "BatchEncoder")
    .def(py::init<ctx_ptr_t>())
    .def("encode", py::overload_cast<const std::vector<std::uint64_t>&, Plaintext&>(&BatchEncoder::encode),
        "Creates a SEAL plaintext from a given matrix")
    .def("encode", py::overload_cast<const std::vector<std::int64_t>&, Plaintext&>(&BatchEncoder::encode),
        "Creates a SEAL plaintext from a given matrix")
    .def("decode_uint64", [](BatchEncoder &e, const Plaintext &plain) {
            std::vector<std::uint64_t> result;
            e.decode(plain, result);
            return result;
        },
        "Inverse of encode")
    .def("decode_int64", [](BatchEncoder &e, const Plaintext &plain) {
            std::vector<std::int64_t> result;
            e.decode(plain, result);
            return result;
        },
        "Inverse of encode")
    .def_property_readonly("slot_count", &BatchEncoder::slot_count,
        "The number of slots.");
}
