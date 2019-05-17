//
// Created by xiamr on 5/16/19.
//

#ifndef DNSSTUB_SETUPINIT_HPP
#define DNSSTUB_SEUEPINIT_HPP

class DnsQueryStatistics;

std::tuple<int,int,int, int , DnsQueryStatistics*>  init(int argc, char *argv[]);

#endif //DNSSTUB_SETUPINIT_HPP
