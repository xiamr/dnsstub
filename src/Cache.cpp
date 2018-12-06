//
// Created by xiamr on 11/27/18.
//

#include "DnsQueryStatistics.h"
#include "Dns.h"
#include <boost/program_options.hpp>
#include "json.hpp"
#include <chrono>       // std::chrono::system_clock
#include <random>       // std::default_random_engine
#include <fmt/printf.h>
#include <boost/algorithm/string.hpp>
#include <regex>
#include <fstream>
#include <unordered_set>
#include <sstream>
#include <sys/timerfd.h>
#include <queue>
#include <unordered_map>
#include <map>
#include <list>
#include <tuple>
#include <vector>
#include <iostream>
#include <sys/types.h>
#include <utility>
#include "Cache.h"


Cache::~Cache() {
  for (auto r : sorted_heap) {
    delete r;
  }
  for (auto &item : item_hash) {
    delete item.second;
  }
}

void Cache::construct(Dns &dns) {
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  double mtime = time.tv_sec + time.tv_nsec * 10e-9;
  for (auto &ans : dns.answers) {
    auto it1 = item_hash.find(ans.name);
    Item *p1, *p2;
    if (it1 == item_hash.end()) {
      p1 = new Item();
      p1->name = ans.name;
      item_hash[p1->name] = p1;
    } else {
      p1 = it1->second;
    }

    auto it2 = item_hash.find(ans.rdata);
    if (it2 == item_hash.end()) {
      p2 = new Item();
      p2->name = ans.rdata;
      item_hash[p2->name] = p2;
    } else {
      p2 = it2->second;
    }

    Relation *relation = nullptr;
    for (auto &r : p1->child_relations) {
      if (r->type == ans.Type) {
        if (r->child_item == p2)
          relation = r;
      }
    }
    bool exist = true;

    if (!relation) {
      exist = false;
      relation = new Relation();
      relation->type = ans.Type;
    }
    relation->parent_item = p1;
    relation->child_item = p2;

    p1->child_relations.insert(relation);
    p2->parent_relations.insert(relation);
    double old = relation->exp_time;
    relation->exp_time = ans.TTL + mtime;
    if (!exist) min_heap_insert(relation);
    else {
      if (relation->exp_time > old) heap_increase_key(relation->i);
      else if (relation->exp_time < old) heap_decrease_key(relation->i);
    }
  }
  set_timer(mtime);
}

void Cache::timeout() {
  // timeout event from epoll
  // remove some relations
  // if no relation link item, remove also
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  double mtime = time.tv_sec + time.tv_nsec * 10e-9;

  for (;;) {
    Relation *r = heap_min();
    if (r and r->exp_time < mtime + 1) {
      r->parent_item->child_relations.erase(r);
      r->child_item->parent_relations.erase(r);

      delete heap_extraxt_min();
      if ((r->parent_item->parent_relations.size() + r->parent_item->child_relations.size()) == 0) {
        item_hash.erase(r->parent_item->name);
        delete r->parent_item;
      }
      if ((r->child_item->parent_relations.size() + r->child_item->child_relations.size()) == 0) {
        item_hash.erase(r->child_item->name);
        delete r->child_item;
      }

      continue;
    }
    break;
  }
  ///
  set_timer(mtime);

}

void Cache::set_timer(double mtime) {
  struct itimerspec itimer;
  itimer.it_interval.tv_nsec = 0;
  itimer.it_interval.tv_sec = 0;

  if (sorted_heap.empty()) {
    itimer.it_value.tv_sec = 0;
  } else {
    itimer.it_value.tv_sec = heap_min()->exp_time;
  }
  itimer.it_value.tv_nsec = 0;
  double ntime = itimer.it_value.tv_sec + itimer.it_value.tv_nsec * 10e-9;
  if (abs(static_cast<int>(ntime - last_timer)) < 1)
    return;
  timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &itimer, nullptr);
  last_timer = ntime;

}

void Cache::heap_decrease_key(int i) {
  while (i > 0 and sorted_heap[PARENT(i)]->exp_time > sorted_heap[i]->exp_time) {
    swap(i, PARENT(i));
    i = PARENT(i);
  }
}

void Cache::heap_increase_key(int i) {
  // left 2*(i+1) - 1  and right 2*(i+1)

  unsigned long size = sorted_heap.size();
  for (;;) {

    int left_child = LEFT_CHILD(i);
    int right_child = RIGHT_CHILD(i);

    if (left_child < size and right_child < size) {
      if (sorted_heap[left_child]->exp_time < sorted_heap[right_child]->exp_time) {
        swap(i, left_child);
        i = left_child;
      } else {
        swap(i, right_child);
        i = right_child;
      }
    } else if (left_child < size) {
      swap(i, left_child);
      i = left_child;
    } else if (right_child < size) {
      swap(i, right_child);
      i = right_child;
    } else {
      break;
    }
  }
}

void Cache::swap(int i, int j) {
  Relation *tmp = sorted_heap[j];
  sorted_heap[j] = sorted_heap[i];
  sorted_heap[i] = tmp;

  sorted_heap[i]->i = i;
  sorted_heap[j]->i = j;

}

Cache::Relation *Cache::heap_extraxt_min() {
  if (sorted_heap.empty()) return nullptr;
  Relation *r = sorted_heap[0];
  sorted_heap[0] = sorted_heap[sorted_heap.size() - 1];
  sorted_heap[0]->i = 0;
  sorted_heap.pop_back();
  heap_increase_key(0);
  return r;
}

Cache::Item *Cache::getItem(const std::__cxx11::string &name) {
  auto it = item_hash.find(name);
  if (it == item_hash.end()) return nullptr;
  else return it->second;
}

void Cache::min_heap_insert(Cache::Relation *key) {
  sorted_heap.push_back(key);
  key->i = sorted_heap.size() - 1;
  heap_decrease_key(key->i);
}
