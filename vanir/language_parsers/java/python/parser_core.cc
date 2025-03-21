// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "vanir/language_parsers/java/parser_core.h"

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "pybind11_abseil/absl_casters.h"
#include "pybind11_abseil/status_casters.h"

namespace vanir {
namespace java_parser {
namespace {

PYBIND11_MODULE(parser_core, m) {
  pybind11::google::ImportStatusModule();
  pybind11::class_<FunctionChunk>(m, "FunctionChunkRaw")
      .def_readonly("name", &FunctionChunk::name_)
      .def_readonly("return_type", &FunctionChunk::return_type_)
      .def_readonly("parameters", &FunctionChunk::parameters_)
      .def_readonly("used_data_types", &FunctionChunk::used_data_types_)
      .def_readonly("local_variables", &FunctionChunk::local_variables_)
      .def_readonly("called_functions", &FunctionChunk::called_functions_)
      .def_readonly("tokens", &FunctionChunk::tokens_)
      .def_readonly("start_line", &FunctionChunk::line_start_)
      .def_readonly("end_line", &FunctionChunk::line_stop_);

  pybind11::class_<LineChunk>(m, "LineChunkRaw")
      .def_readonly("tokens_", &LineChunk::tokens_);

  pybind11::class_<ParseError>(m, "ParseErrorRaw")
      .def_readonly("line", &ParseError::line)
      .def_readonly("column", &ParseError::column)
      .def_readonly("bad_token", &ParseError::bad_token)
      .def_readonly("message", &ParseError::message);

  pybind11::class_<ParserCore>(m, "ParserCore")
      .def(pybind11::init<std::string>())
      .def("parse", &ParserCore::Parse,
           pybind11::arg("affected_line_ranges_for_functions"));
}

}  // namespace
}  // namespace java_parser
}  // namespace vanir
