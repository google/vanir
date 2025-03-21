// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "vanir/language_parsers/cpp/parser_core.h"

#include "pybind11/pybind11.h"
#include "pybind11_abseil/absl_casters.h"
#include "pybind11_abseil/status_casters.h"

namespace vanir {
namespace cpp_parser {
namespace {

PYBIND11_MODULE(parser_core, m) {
  pybind11::google::ImportStatusModule();
  pybind11::class_<FunctionChunk>(m, "FunctionChunkRaw")
      .def_readwrite("name", &FunctionChunk::name_)
      .def_readwrite("return_type", &FunctionChunk::return_type_)
      .def_readwrite("parameters", &FunctionChunk::parameters_)
      // Since individual data type element can be used after freeing the owner
      // chunk in Python, access to used_data_types_ transfers the ownership of
      // individual data type element to Python.
      .def_property_readonly("used_data_types",
           [](const FunctionChunk& func_chunk) {
             auto used_data_types = pybind11::list();
             for (auto& data_type : func_chunk.used_data_types_) {
               used_data_types.append(pybind11::cast(
                   *data_type, pybind11::return_value_policy::take_ownership));
             }
             return used_data_types;
           })
      .def_readwrite("local_variables", &FunctionChunk::local_variables_)
      .def_readwrite("called_functions", &FunctionChunk::called_functions_)
      .def_readwrite("tokens", &FunctionChunk::tokens_);

  pybind11::class_<LineChunk>(m, "LineChunkRaw")
      .def_readwrite("tokens", &LineChunk::tokens_);

  pybind11::class_<ParseError>(m, "ParseErrorRaw")
      .def_readonly("line", &ParseError::line)
      .def_readonly("column", &ParseError::column)
      .def_readonly("bad_token", &ParseError::bad_token)
      .def_readonly("message", &ParseError::message);

  // GetFunctionChunks and GetLineChunk transfer the ownership.
  pybind11::class_<ParserCore>(m, "ParserCore")
      .def(pybind11::init<std::string>())
      .def("init", &ParserCore::Init)
      .def("get_function_chunks", &ParserCore::GetFunctionChunks,
           pybind11::arg("affected_line_ranges"))
      .def("get_line_chunk", &ParserCore::GetLineChunk)
      .def("get_parse_errors", &ParserCore::GetParseErrors);
}

}  // namespace
}  // namespace cpp_parser
}  // namespace vanir
