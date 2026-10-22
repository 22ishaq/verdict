// pybind11 bindings that expose the NR-Lite testbed to Verdict.
//
// The binding deliberately exposes *mechanism* (time, air interface, injection, inspection) and the
// stack's own decoders and crypto only for cross-checking. Verdict's system simulator builds and
// verifies messages with its own Python codecs and security implementation.

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <memory>
#include <string>
#include <vector>

#include "nrlite/nas/messages.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/security/aka.hpp"
#include "nrlite/security/kdf.hpp"
#include "nrlite/security/milenage.hpp"
#include "nrlite/sim/simulator.hpp"

namespace py = pybind11;
using namespace nrlite;

namespace {

py::bytes to_py(const Bytes& b) { return py::bytes(reinterpret_cast<const char*>(b.data()), b.size()); }

Bytes from_py(const py::bytes& b) {
  const std::string s = b;
  return Bytes(s.begin(), s.end());
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed_from_py(const py::bytes& b, const char* what) {
  const Bytes v = from_py(b);
  if (v.size() != N) throw py::value_error(std::string(what) + " must be " + std::to_string(N) + " bytes");
  std::array<std::uint8_t, N> out{};
  std::copy(v.begin(), v.end(), out.begin());
  return out;
}

template <std::size_t N>
py::bytes arr_to_py(const std::array<std::uint8_t, N>& a) {
  return py::bytes(reinterpret_cast<const char*>(a.data()), N);
}

rrc::Channel parse_channel(const std::string& c) {
  if (c == "CCCH") return rrc::Channel::Ccch;
  if (c == "DCCH") return rrc::Channel::Dcch;
  throw py::value_error("channel must be 'CCCH' or 'DCCH'");
}

LogLevel parse_level(const std::string& s) {
  if (s == "debug") return LogLevel::Debug;
  if (s == "info") return LogLevel::Info;
  if (s == "warn") return LogLevel::Warn;
  if (s == "error") return LogLevel::Error;
  if (s == "off") return LogLevel::Off;
  throw py::value_error("log level must be debug|info|warn|error|off");
}

py::dict air_pdu_dict(const sim::AirPdu& p) {
  py::dict d;
  d["rnti"] = p.rnti;
  d["direction"] = p.direction == sim::Direction::Uplink ? "UL" : "DL";
  d["channel"] = p.channel == rrc::Channel::Ccch ? "CCCH" : "DCCH";
  d["data"] = to_py(p.data);
  return d;
}

py::object timer_view(const Timer& t) {
  if (!t.running()) return py::none();
  return py::int_(t.remaining());
}

void apply_gnb(rrc::GnbConfig& c, const py::dict& d) {
  for (auto item : d) {
    const std::string k = py::str(item.first);
    py::handle v = item.second;
    if (k == "max_ues") c.max_ues = v.cast<std::size_t>();
    else if (k == "reject_wait_time_s") c.reject_wait_time_s = v.cast<std::uint8_t>();
    else if (k == "reject_all") c.reject_all = v.cast<bool>();
    else if (k == "setup_complete_timeout_ms") c.setup_complete_timeout_ms = v.cast<TimeMs>();
    else if (k == "security_mode_timeout_ms") c.security_mode_timeout_ms = v.cast<TimeMs>();
    else if (k == "ciphering") {
      const std::string s = v.cast<std::string>();
      if (s == "nea0") c.ciphering = rrc::CipheringAlgorithm::nea0;
      else if (s == "nea2") c.ciphering = rrc::CipheringAlgorithm::nea2;
      else throw py::value_error("gnb ciphering must be nea0 or nea2");
    } else throw py::key_error("unknown gNB option: " + k);
  }
}

nas::GprsTimer timer_from(py::handle v) {
  auto t = v.cast<std::pair<int, int>>();
  return nas::GprsTimer{static_cast<std::uint8_t>(t.first), static_cast<std::uint8_t>(t.second)};
}

void apply_amf(core::AmfConfig& c, const py::dict& d) {
  for (auto item : d) {
    const std::string k = py::str(item.first);
    py::handle v = item.second;
    if (k == "t3550_ms") c.t3550_ms = v.cast<TimeMs>();
    else if (k == "t3560_ms") c.t3560_ms = v.cast<TimeMs>();
    else if (k == "t3570_ms") c.t3570_ms = v.cast<TimeMs>();
    else if (k == "max_retransmissions") c.max_retransmissions = v.cast<unsigned>();
    else if (k == "integrity_preference") c.integrity_preference = v.cast<std::vector<std::uint8_t>>();
    else if (k == "ciphering_preference") c.ciphering_preference = v.cast<std::vector<std::uint8_t>>();
    else if (k == "release_after_registration") c.release_after_registration = v.cast<bool>();
    else if (k == "release_delay_ms") c.release_delay_ms = v.cast<TimeMs>();
    else if (k == "request_imeisv") c.request_imeisv = v.cast<bool>();
    else if (k == "request_initial_message_resend") c.request_initial_message_resend = v.cast<bool>();
    else if (k == "t3512") c.t3512 = timer_from(v);
    else if (k == "tac") c.tac = v.cast<std::uint32_t>();
    else if (k == "reject_registrations_with") {
      if (v.is_none()) c.reject_registrations_with.reset();
      else c.reject_registrations_with = static_cast<nas::Cause>(v.cast<int>());
    } else if (k == "reject_t3346") {
      if (v.is_none()) c.reject_t3346.reset();
      else c.reject_t3346 = timer_from(v);
    } else throw py::key_error("unknown AMF option: " + k);
  }
}

sim::UeConfig ue_config(std::size_t index, const py::dict& d) {
  sim::UeConfig c = sim::Simulator::default_ue_config(index);
  for (auto item : d) {
    const std::string k = py::str(item.first);
    py::handle v = item.second;
    if (k == "name") c.name = v.cast<std::string>();
    else if (k == "supi") c.nas.subscription.supi = v.cast<std::string>();
    else if (k == "k") c.nas.subscription.k = fixed_from_py<16>(v.cast<py::bytes>(), "k");
    else if (k == "opc") c.nas.subscription.opc = fixed_from_py<16>(v.cast<py::bytes>(), "opc");
    else if (k == "sqn") c.nas.sqn_ms = v.cast<std::uint64_t>();
    else if (k == "imeisv") c.nas.imeisv = v.cast<std::string>();
    else if (k == "t300_ms") c.rrc.t300_ms = v.cast<TimeMs>();
    else if (k == "t3510_ms") c.nas.t3510_ms = v.cast<TimeMs>();
    else if (k == "t3511_ms") c.nas.t3511_ms = v.cast<TimeMs>();
    else if (k == "t3502_ms") c.nas.t3502_ms = v.cast<TimeMs>();
    else if (k == "t3520_ms") c.nas.t3520_ms = v.cast<TimeMs>();
    else if (k == "t3521_ms") c.nas.t3521_ms = v.cast<TimeMs>();
    else if (k == "security_capability") {
      auto p = v.cast<std::pair<int, int>>();
      c.nas.security_capability.nr_ea = static_cast<std::uint8_t>(p.first);
      c.nas.security_capability.nr_ia = static_cast<std::uint8_t>(p.second);
    } else throw py::key_error("unknown UE option: " + k);
  }
  return c;
}

/// Owns a Simulator plus the trace, log buffer and the Python callables wired into it.
class PySimulator {
 public:
  PySimulator(std::uint64_t seed, TimeMs air_latency_ms, TimeMs n2_latency_ms, const std::string& log_level,
              const py::dict& gnb, const py::dict& amf) {
    sim::SimConfig cfg;
    cfg.seed = seed;
    cfg.air_latency_ms = air_latency_ms;
    cfg.n2_latency_ms = n2_latency_ms;
    cfg.log_level = parse_level(log_level);
    apply_gnb(cfg.gnb, gnb);
    apply_amf(cfg.amf, amf);
    sim_ = std::make_unique<sim::Simulator>(cfg);
    sim_->add_trace_sink(&trace_);
    sim_->logger().set_sink([this](LogLevel lvl, TimeMs t, const std::string& comp, const std::string& text) {
      if (logs_.size() < 50'000) logs_.push_back({t, to_string(lvl), comp, text});
    });
  }

  std::size_t add_ue(bool provision, const py::dict& opts) {
    sim_->add_ue(ue_config(sim_->ue_count(), opts), provision);
    return sim_->ue_count() - 1;
  }

  sim::UeNode& ue(std::size_t i) {
    if (i >= sim_->ue_count()) throw py::index_error("no such UE");
    return sim_->ue(i);
  }

  py::dict ue_state(std::size_t i) {
    sim::UeNode& u = ue(i);
    const auto& nas = u.nas();
    const auto& rrc = u.rrc();
    py::dict d;
    d["name"] = u.config().name;
    d["supi"] = u.config().nas.subscription.supi;
    d["rnti"] = u.rnti();
    d["rrc"] = rrc::to_string(rrc.state());
    d["as_security"] = rrc.as_security_active();
    d["mm"] = nas::to_string(nas.state());
    d["mm_sub"] = nas::to_string(nas.sub_state());
    d["mode"] = nas::to_string(nas.mode());
    d["attempt_counter"] = nas.attempt_counter();
    d["usim_sqn"] = nas.usim().sqn_ms();
    if (nas.guti()) {
      py::dict g;
      g["amf_region_id"] = nas.guti()->amf_region_id;
      g["amf_set_id"] = nas.guti()->amf_set_id;
      g["amf_pointer"] = nas.guti()->amf_pointer;
      g["tmsi"] = nas.guti()->tmsi;
      g["s_tmsi"] = nas.guti()->s_tmsi();
      d["guti"] = g;
    } else {
      d["guti"] = py::none();
    }
    const auto& ctx = nas.security_context();
    py::dict s;
    s["valid"] = ctx.valid;
    s["ngksi"] = ctx.ngksi.ksi;
    s["ul_count"] = ctx.ul_count;
    s["dl_count"] = ctx.dl_count;
    s["ea"] = ctx.algorithms.ciphering;
    s["ia"] = ctx.algorithms.integrity;
    d["security"] = s;
    py::dict t;
    t["T300"] = timer_view(rrc.t300());
    t["T302"] = timer_view(rrc.t302());
    t["T3510"] = timer_view(nas.t3510());
    t["T3511"] = timer_view(nas.t3511());
    t["T3502"] = timer_view(nas.t3502());
    t["T3512"] = timer_view(nas.t3512());
    t["T3520"] = timer_view(nas.t3520());
    t["T3521"] = timer_view(nas.t3521());
    t["T3346"] = timer_view(nas.t3346());
    d["timers"] = t;
    py::dict c;
    c["rrc_setup_requests"] = rrc.counters().setup_requests;
    c["rrc_decode_errors"] = rrc.counters().decode_errors;
    c["rrc_integrity_failures"] = rrc.counters().integrity_failures;
    c["rrc_ignored"] = rrc.counters().ignored_messages;
    c["rrc_security_mode_failures"] = rrc.counters().security_mode_failures;
    c["nas_registration_attempts"] = nas.counters().registration_attempts;
    c["nas_discarded_plain"] = nas.counters().discarded_plain;
    c["nas_integrity_failures"] = nas.counters().integrity_failures;
    c["nas_decode_errors"] = nas.counters().decode_errors;
    c["nas_status_sent"] = nas.counters().status_sent;
    c["nas_auth_failures_sent"] = nas.counters().auth_failures_sent;
    d["counters"] = c;
    return d;
  }

  py::list trace() const {
    py::list out;
    for (const auto& r : trace_.records()) {
      py::dict d;
      d["time"] = r.time;
      d["iface"] = r.iface == sim::Interface::Uu ? "Uu" : "N2";
      d["direction"] = sim::to_string(r.direction);
      d["channel"] = r.channel;
      d["rnti"] = r.rnti;
      d["ran_ue_id"] = r.ran_ue_id;
      d["raw"] = to_py(r.raw);
      d["payload"] = to_py(r.payload);
      d["message"] = r.message;
      d["dropped"] = r.dropped;
      out.append(d);
    }
    return out;
  }

  py::list logs() const {
    py::list out;
    for (const auto& l : logs_) out.append(py::make_tuple(l.time, l.level, l.component, l.text));
    return out;
  }

  void set_interceptor(py::object fn) {
    interceptor_ = fn;
    if (fn.is_none()) {
      sim_->set_air_interceptor(nullptr);
      return;
    }
    sim_->set_air_interceptor([this](sim::AirPdu& pdu) {
      py::object r = interceptor_(air_pdu_dict(pdu));
      if (r.is_none()) return sim::InterceptDecision::deliver();
      if (py::isinstance<py::str>(r)) {
        if (r.cast<std::string>() == "drop") return sim::InterceptDecision::drop();
        throw py::value_error("interceptor may return None, 'drop', a delay in ms, or replacement bytes");
      }
      if (py::isinstance<py::bytes>(r)) {
        pdu.data = from_py(r.cast<py::bytes>());
        return sim::InterceptDecision::deliver();
      }
      if (py::isinstance<py::int_>(r) || py::isinstance<py::float_>(r)) {
        return sim::InterceptDecision::delay(r.cast<TimeMs>());
      }
      throw py::value_error("interceptor may return None, 'drop', a delay in ms, or replacement bytes");
    });
  }

  void detach_gnb(py::object fn) {
    uplink_handler_ = fn;
    sim_->detach_gnb([this](const sim::AirPdu& pdu) { uplink_handler_(air_pdu_dict(pdu)); });
  }

  void set_downlink_handler(py::object fn) {
    downlink_handler_ = fn;
    if (fn.is_none()) {
      sim_->set_downlink_handler(nullptr);
      return;
    }
    sim_->set_downlink_handler([this](const sim::AirPdu& pdu) { downlink_handler_(air_pdu_dict(pdu)); });
  }

  bool run_until(const py::function& pred, TimeMs limit) {
    return sim_->run_until([&pred] { return pred().cast<bool>(); }, limit);
  }

  void start_pcap(const std::string& path, bool include_n2) {
    stop_pcap();
    pcap_ = std::make_unique<sim::PcapTrace>(path, include_n2);
    sim_->add_trace_sink(pcap_.get());
  }

  void stop_pcap() {
    if (pcap_) {
      sim_->remove_trace_sink(pcap_.get());
      pcap_->flush();
      pcap_.reset();
    }
  }

  py::dict amf_ue(const std::string& supi) const {
    py::dict d;
    const auto v = sim_->amf().ue(supi);
    if (!v) return d;
    d["state"] = core::to_string(v->state);
    d["connected"] = v->connected;
    d["security_active"] = v->security_active;
    d["ul_count"] = v->ul_count;
    d["dl_count"] = v->dl_count;
    d["tmsi"] = v->guti ? py::object(py::int_(v->guti->tmsi)) : py::object(py::none());
    return d;
  }

  py::dict amf_counters() const {
    const auto& c = sim_->amf().counters();
    py::dict d;
    d["registrations_completed"] = c.registrations_completed;
    d["registration_rejects"] = c.registration_rejects;
    d["authentications"] = c.authentications;
    d["auth_failures"] = c.auth_failures;
    d["resyncs"] = c.resyncs;
    d["integrity_failures"] = c.integrity_failures;
    d["decode_errors"] = c.decode_errors;
    d["discarded_plain"] = c.discarded_plain;
    d["retransmissions"] = c.retransmissions;
    d["deregistrations"] = c.deregistrations;
    return d;
  }

  py::dict gnb_counters() const {
    const auto& c = sim_->gnb().counters();
    py::dict d;
    d["ue_count"] = sim_->gnb().ue_count();
    d["setups"] = c.setups;
    d["rejects"] = c.rejects;
    d["decode_errors"] = c.decode_errors;
    d["integrity_failures"] = c.integrity_failures;
    d["ignored_messages"] = c.ignored_messages;
    d["guard_expiries"] = c.guard_expiries;
    d["releases"] = c.releases;
    return d;
  }

  sim::Simulator& sim() { return *sim_; }
  sim::MemoryTrace& memory_trace() { return trace_; }

 private:
  struct LogLine {
    TimeMs time;
    std::string level, component, text;
  };
  std::unique_ptr<sim::Simulator> sim_;
  sim::MemoryTrace trace_;
  std::unique_ptr<sim::PcapTrace> pcap_;
  std::vector<LogLine> logs_;
  py::object interceptor_ = py::none();
  py::object uplink_handler_ = py::none();
  py::object downlink_handler_ = py::none();
};

std::string decode_rrc_json(const std::string& channel, const py::bytes& data) {
  const Bytes b = from_py(data);
  auto render = [](const auto& r) -> std::string {
    if (!r) throw py::value_error(r.error().message);
    return rrc::to_json(*r).dump();
  };
  if (channel == "UL-CCCH") return render(rrc::decode_ul_ccch(b));
  if (channel == "DL-CCCH") return render(rrc::decode_dl_ccch(b));
  if (channel == "UL-DCCH") return render(rrc::decode_ul_dcch(b));
  if (channel == "DL-DCCH") return render(rrc::decode_dl_dcch(b));
  throw py::value_error("channel must be UL-CCCH, DL-CCCH, UL-DCCH or DL-DCCH");
}

std::string decode_nas_json(const py::bytes& data) {
  auto r = nas::decode_plain(from_py(data));
  if (!r) throw py::value_error(r.error().message + " (cause #" + std::to_string(r.error().code) + ")");
  return nas::to_json(*r).dump();
}

}  // namespace

PYBIND11_MODULE(_nrlite, m) {
  m.doc() = "NR-Lite testbed bindings for Verdict";

  py::class_<PySimulator>(m, "Simulator")
      .def(py::init<std::uint64_t, TimeMs, TimeMs, const std::string&, const py::dict&, const py::dict&>(),
           py::arg("seed") = 1, py::arg("air_latency_ms") = 2, py::arg("n2_latency_ms") = 1,
           py::arg("log_level") = "info", py::arg("gnb") = py::dict(), py::arg("amf") = py::dict())
      // time
      .def("now", [](PySimulator& s) { return s.sim().now(); })
      .def("advance", [](PySimulator& s, TimeMs ms) { s.sim().advance(ms); }, py::arg("ms"))
      .def("step", [](PySimulator& s) { return s.sim().loop().step(); })
      .def("next_event_time", [](PySimulator& s) { return s.sim().loop().next_event_time(); })
      .def("run_until", &PySimulator::run_until, py::arg("predicate"), py::arg("limit_ms"))
      // UEs
      .def("add_ue", &PySimulator::add_ue, py::arg("provision") = true, py::arg("options") = py::dict())
      .def("ue_count", [](PySimulator& s) { return s.sim().ue_count(); })
      .def("ue_state", &PySimulator::ue_state, py::arg("index") = 0)
      .def("ue_power_on", [](PySimulator& s, std::size_t i) { s.ue(i).nas().power_on(); }, py::arg("index") = 0)
      .def("ue_power_off", [](PySimulator& s, std::size_t i) { s.ue(i).nas().power_off(); }, py::arg("index") = 0)
      .def("ue_register", [](PySimulator& s, std::size_t i) { return s.ue(i).nas().register_ue(); }, py::arg("index") = 0)
      .def("ue_deregister", [](PySimulator& s, std::size_t i, bool off) { return s.ue(i).nas().deregister(off); },
           py::arg("index") = 0, py::arg("switch_off") = false)
      .def("ue_set_usim_sqn", [](PySimulator& s, std::size_t i, std::uint64_t v) { s.ue(i).nas().usim().set_sqn_ms(v); },
           py::arg("index"), py::arg("sqn"))
      // gNB / AMF
      .def("gnb_counters", &PySimulator::gnb_counters)
      .def("gnb_ue_state", [](PySimulator& s, std::uint16_t rnti) -> py::object {
        const auto st = s.sim().gnb().state_of(rnti);
        if (!st) return py::none();
        return py::str(rrc::to_string(*st));
      })
      .def("configure_gnb", [](PySimulator& s, py::kwargs kw) { apply_gnb(s.sim().gnb().config(), kw); })
      .def("configure_amf", [](PySimulator& s, py::kwargs kw) { apply_amf(s.sim().amf().config(), kw); })
      .def("amf_ue", &PySimulator::amf_ue, py::arg("supi"))
      .def("amf_counters", &PySimulator::amf_counters)
      .def("amf_add_subscriber",
           [](PySimulator& s, const std::string& supi, const py::bytes& k, const py::bytes& opc, std::uint64_t sqn) {
             sec::Subscription sub;
             sub.supi = supi;
             sub.k = fixed_from_py<16>(k, "k");
             sub.opc = fixed_from_py<16>(opc, "opc");
             s.sim().amf().add_subscriber(sub, sqn);
           },
           py::arg("supi"), py::arg("k"), py::arg("opc"), py::arg("sqn") = 0)
      .def("amf_subscriber_sqn", [](PySimulator& s, const std::string& supi) { return s.sim().amf().subscriber_sqn(supi); })
      // air interface
      .def("set_air_interceptor", &PySimulator::set_interceptor, py::arg("fn"))
      .def("detach_gnb", &PySimulator::detach_gnb, py::arg("uplink_handler"))
      .def("reattach_gnb", [](PySimulator& s) { s.sim().reattach_gnb(); })
      .def("set_downlink_handler", &PySimulator::set_downlink_handler, py::arg("fn"))
      .def("inject_dl",
           [](PySimulator& s, std::uint16_t rnti, const std::string& ch, const py::bytes& data, const py::bytes& hint) {
             s.sim().inject_dl(rnti, parse_channel(ch), from_py(data), from_py(hint));
           },
           py::arg("rnti"), py::arg("channel"), py::arg("data"), py::arg("rrc_hint") = py::bytes())
      .def("inject_ul",
           [](PySimulator& s, std::uint16_t rnti, const std::string& ch, const py::bytes& data, const py::bytes& hint) {
             s.sim().inject_ul(rnti, parse_channel(ch), from_py(data), from_py(hint));
           },
           py::arg("rnti"), py::arg("channel"), py::arg("data"), py::arg("rrc_hint") = py::bytes())
      // observation
      .def("trace", &PySimulator::trace)
      .def("clear_trace", [](PySimulator& s) { s.memory_trace().clear(); })
      .def("logs", &PySimulator::logs)
      .def("start_pcap", &PySimulator::start_pcap, py::arg("path"), py::arg("include_n2") = true)
      .def("stop_pcap", &PySimulator::stop_pcap);

  // The stack's own codecs, for cross-checking Verdict's independent implementation.
  m.def("decode_rrc", &decode_rrc_json, py::arg("channel"), py::arg("data"),
        "Decode an RRC PDU with NR-Lite; returns JSON text (raises ValueError on malformed input).");
  m.def("decode_nas", &decode_nas_json, py::arg("data"), "Decode a plain 5GMM message with NR-Lite (JSON text).");

  // The stack's own crypto, for cross-checking.
  m.def("milenage",
        [](const py::bytes& k, const py::bytes& opc, const py::bytes& rand, const py::bytes& sqn, const py::bytes& amf) {
          const sec::Milenage mil(fixed_from_py<16>(k, "k"), fixed_from_py<16>(opc, "opc"));
          const auto r = fixed_from_py<16>(rand, "rand");
          const auto f1 = mil.f1(r, fixed_from_py<6>(sqn, "sqn"), fixed_from_py<2>(amf, "amf"));
          const auto f = mil.f2345(r);
          py::dict d;
          d["mac_a"] = arr_to_py(f1.mac_a);
          d["mac_s"] = arr_to_py(f1.mac_s);
          d["res"] = arr_to_py(f.res);
          d["ck"] = arr_to_py(f.ck);
          d["ik"] = arr_to_py(f.ik);
          d["ak"] = arr_to_py(f.ak);
          d["ak_star"] = arr_to_py(mil.f5_star(r));
          return d;
        });
  m.def("nia2", [](const py::bytes& key, std::uint32_t count, std::uint8_t bearer, int direction, const py::bytes& msg) {
    return arr_to_py(sec::nia2(fixed_from_py<16>(key, "key"), count, bearer,
                               direction ? sec::Direction::Downlink : sec::Direction::Uplink, from_py(msg)));
  });
  m.def("nea2", [](const py::bytes& key, std::uint32_t count, std::uint8_t bearer, int direction, const py::bytes& data) {
    return to_py(sec::nea2(fixed_from_py<16>(key, "key"), count, bearer,
                           direction ? sec::Direction::Downlink : sec::Direction::Uplink, from_py(data)));
  });
  m.def("kdf", [](const py::bytes& key, std::uint8_t fc, const std::vector<py::bytes>& params) {
    std::vector<Bytes> ps;
    for (const auto& p : params) ps.push_back(from_py(p));
    return arr_to_py(sec::kdf(from_py(key), fc, ps));
  });
}
