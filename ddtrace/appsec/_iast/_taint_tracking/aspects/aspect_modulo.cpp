#include "aspect_modulo.h"

static PyObject*
do_modulo(PyObject* text, PyObject* insert_tuple_or_obj)
{
    // Early return: if left operand is not text-like, preserve native % behavior.
    // Do NOT coerce the right operand to a tuple; arithmetic expects the raw operand.

    // Keep borrowed parameters non-owning and retain only a tuple created here.
    py::handle params(insert_tuple_or_obj);
    py::object owned_params;
    if (!PyTuple_Check(insert_tuple_or_obj) && !PyMapping_Check(insert_tuple_or_obj)) {
        owned_params = py::reinterpret_steal<py::object>(PyTuple_Pack(1, insert_tuple_or_obj));
        if (!owned_params) {
            return nullptr;
        }
        params = owned_params;
    }

    PyObject* result = nullptr;
    if (PyUnicode_Check(text)) {
        result = PyUnicode_Format(text, params.ptr());
    } else if (PyBytes_Check(text) || PyByteArray_Check(text)) {
        // Use generic numeric remainder which maps to % operator without creating a method name
        result = PyNumber_Remainder(text, params.ptr());
    } else {
        // Fallback: try generic % operator; if unsupported, Python will raise
        result = PyNumber_Remainder(text, params.ptr());
    }

    // result is a new reference from PyUnicode_Format/PyNumber_Remainder; return as-is
    return result;
}

PyObject*
api_modulo_aspect(PyObject* self, PyObject* const* args, const Py_ssize_t nargs)
{
    if (nargs != 3) {
        py::set_error(PyExc_ValueError, MSG_ERROR_N_PARAMS);
        return nullptr;
    }
    PyObject* candidate_text = args[0];
    PyObject* candidate_tuple = args[1];
    PyObject* candidate_result = args[2]; // borrowed from caller

    // Helper: return the precomputed result safely (INCREF because it's a borrowed ref)
    auto return_candidate_result = [&]() -> PyObject* {
        if (candidate_result == nullptr) {
            // propagate error if any
            return nullptr;
        }
        Py_INCREF(candidate_result);
        return candidate_result;
    };

    CHECK_IAST_INITIALIZED_OR_RETURN(return_candidate_result());

    TRY_CATCH_ASPECT("modulo_aspect", return return_candidate_result(), , {
        const auto tx_map = safe_get_tainted_object_map_from_list_of_pyobjects({ candidate_text, candidate_tuple });
        if (!tx_map || tx_map->empty()) {
            return return_candidate_result();
        }

        const auto py_candidate_text = py::reinterpret_borrow<py::object>(candidate_text);
        auto py_candidate_tuple = py::reinterpret_borrow<py::object>(candidate_tuple);

        const auto py_str_type = get_pytext_type(candidate_text);
        if (py_str_type == PyTextType::OTHER) {
            // Not a text formatting case; use the already computed result
            return return_candidate_result();
        }

        bool mapping_parameters = PyDict_CheckExact(candidate_tuple);
#if PY_VERSION_HEX >= 0x030F0000
        mapping_parameters = mapping_parameters || PyFrozenDict_CheckExact(candidate_tuple);
#endif
        py::object mapping_items;
        py::tuple parameters;
        if (mapping_parameters) {
            // Snapshot strong references before formatting can allocate or call Python.
            mapping_items = py::reinterpret_steal<py::list>(PyDict_Items(candidate_tuple));
            if (!mapping_items) {
                throw py::error_already_set();
            }
            py::list values;
            for (const auto item : mapping_items) {
                const auto pair = py::reinterpret_borrow<py::tuple>(item);
                const auto key = pair[0];
                // Rebuilding the evidence mapping must not call user-defined key hashing.
                if (!PyUnicode_CheckExact(key.ptr()) && !PyBytes_CheckExact(key.ptr())) {
                    return return_candidate_result();
                }
                values.append(pair[1]);
            }
            parameters = py::tuple(values);
        } else {
            parameters =
              py::isinstance<py::tuple>(py_candidate_tuple) ? py_candidate_tuple : py::make_tuple(py_candidate_tuple);
        }

        auto [ranges_orig, candidate_text_ranges] = are_all_text_all_ranges(candidate_text, parameters, tx_map);

        if (ranges_orig.empty()) {
            return return_candidate_result();
        }

        auto std_candidate_text = py_candidate_text.cast<string>();
        auto fmttext = as_formatted_evidence(std_candidate_text, candidate_text_ranges, TagMappingMode::Mapper);
        py::list list_formatted_parameters;

        for (const py::handle& param_handle : parameters) {
            if (is_text(param_handle.ptr())) {
                auto [ranges, ranges_error] = get_ranges(param_handle.ptr(), tx_map);
                string n_parameter =
                  as_formatted_evidence(AnyTextObjectToString(param_handle), ranges, TagMappingMode::Mapper, nullopt);
                list_formatted_parameters.append(StringToPyObject(n_parameter, py_str_type));
            } else {
                // A second formatting pass must not invoke a mapping value's conversion hooks again.
                if (mapping_parameters && !PyLong_CheckExact(param_handle.ptr()) &&
                    !PyFloat_CheckExact(param_handle.ptr()) && !PyBool_Check(param_handle.ptr()) &&
                    param_handle.ptr() != Py_None) {
                    return return_candidate_result();
                }
                list_formatted_parameters.append(param_handle);
            }
        }
        py::object formatted_parameters;
        if (mapping_parameters) {
            py::dict formatted_mapping;
            Py_ssize_t index = 0;
            for (const auto item : mapping_items) {
                const auto pair = py::reinterpret_borrow<py::tuple>(item);
                formatted_mapping[pair[0]] = list_formatted_parameters[index++];
            }
            formatted_parameters = std::move(formatted_mapping);
        } else {
            formatted_parameters = py::tuple(list_formatted_parameters);
        }

        py::object applied_params = py::reinterpret_steal<py::object>(
          do_modulo(StringToPyObject(fmttext, py_str_type).ptr(), formatted_parameters.ptr()));
        if (!applied_params) {
            return return_candidate_result();
        }

        auto res_pyobject = api_convert_escaped_text_to_taint_text(applied_params.ptr(), ranges_orig, py_str_type);
        if (res_pyobject == nullptr) {
            return return_candidate_result();
        }
        auto result = py::reinterpret_steal<py::object>(res_pyobject);
        // Width or precision can truncate evidence markers. Preserve Python's result in that case.
        if (mapping_parameters && !result.equal(py::handle(candidate_result))) {
            return return_candidate_result();
        }
        return result.release().ptr();
    });
}
