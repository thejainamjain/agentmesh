#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <chrono>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

namespace py = pybind11;

// ---------- Canonical JSON (same as Python logic) ----------
static std::string canonical_json(const py::dict &d)
{
    std::ostringstream out;
    out << "{";

    std::vector<std::string> keys;
    for (auto &item : d)
    {
        keys.push_back(py::str(item.first).cast<std::string>());
    }
    std::sort(keys.begin(), keys.end());

    py::module_ json = py::module_::import("json");

    for (size_t i = 0; i < keys.size(); ++i)
    {
        if (i > 0)
            out << ",";
        out << "\"" << keys[i] << "\":";

        py::object val = d[py::str(keys[i])];
        std::string val_str = json.attr("dumps")(
                                      val,
                                      py::arg("sort_keys") = true,
                                      py::arg("separators") = py::make_tuple(",", ":"))
                                  .cast<std::string>();

        out << val_str;
    }

    out << "}";
    return out.str();
}

// ---------- SHA256 ----------
static std::string sha256_hex(const std::string &input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(), hash);

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');

    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        hex << std::setw(2) << static_cast<int>(hash[i]);

    return hex.str();
}

// ---------- REQUIRED FUNCTION (Python expects THIS) ----------
static std::pair<std::string, std::string> capture(
    const std::string &agent_id,
    const std::string &tool_name,
    const py::dict &arguments)
{
    if (agent_id.empty())
        throw std::invalid_argument("agent_id must not be empty");

    if (tool_name.empty())
        throw std::invalid_argument("tool_name must not be empty");

    // Hash arguments
    std::string canonical = canonical_json(arguments);
    std::string args_hash = sha256_hex(canonical);

    // Timestamp (ISO format)
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");

    return {ts.str(), args_hash};
}

// ---------- PYBIND ----------
PYBIND11_MODULE(interceptor_core, m)
{
    m.doc() = "AgentMesh C++ interceptor core";

    m.def("capture", &capture,
          py::arg("agent_id"),
          py::arg("tool_name"),
          py::arg("arguments"));

    m.attr("__version__") = "0.1.0";
    m.attr("__cpp_path__") = true;
}