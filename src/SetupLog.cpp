//
// Created by xiamr on 5/16/19.
//

#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>


#include "SetupLog.hpp"
#include "Config.h"


BOOST_LOG_ATTRIBUTE_KEYWORD(log_timestamp, "TimeStamp", boost::posix_time::ptime)

void boost_log_init(Config *config) {
  boost::log::add_common_attributes();

// setup console log
  boost::log::add_console_log(
      std::clog,
      boost::log::keywords::filter = boost::log::trivial::severity >= config->current_severity,
      boost::log::keywords::format = (
          boost::log::expressions::stream
              << boost::log::expressions::format_date_time(log_timestamp, "%Y-%m-%d %H:%M:%S")
              << " ["
              << boost::log::trivial::severity
              << "] "
              << boost::log::expressions::smessage
      )
  );
}