//
// Created by xiamr on 11/27/18.
//

#ifndef DNSSTUB_CACHE_H
#define DNSSTUB_CACHE_H

class Dns;

class Cache {
public:
  class Item;

  class Relation {
  public:
    Dns::QType type;
    Item *parent_item;
    Item *child_item;
    double exp_time;
    int i;
  };

  enum ItemType {
    A, AAAA, _DOMAIN
  };

  class Item {
  public:
    std::string name;
    std::unordered_set<Relation *> parent_relations;
    std::unordered_set<Relation *> child_relations;
  };

  void construct(Dns &dns);

  Item *getItem(const std::string &name);


  virtual ~Cache();

  void timeout();

  void set_timer_fd(int timer_fd) {
    this->timer_fd = timer_fd;
  }

  std::unordered_set<std::string> noipv6_domain;
private:
  std::unordered_map<std::string, Item *> item_hash;

  std::vector<Relation *> sorted_heap;
  int timer_fd;
  double last_timer = 0.0;

  void set_timer(double mtime);

  void min_heap_insert(Relation *key);

  int PARENT(int i) { return (i + 1) / 2 - 1; }

  int LEFT_CHILD(int i) { return 2 * (i + 1) - 1; }

  int RIGHT_CHILD(int i) { return 2 * (i + 1); }

  void heap_decrease_key(int i);

  void heap_increase_key(int i);

  void swap(int i, int j);


  Relation *heap_min() {
    if (sorted_heap.empty()) return nullptr;
    return sorted_heap[0];
  }

  Relation *heap_extraxt_min();


};

#endif //DNSSTUB_CACHE_H
