#ifndef CAPACITY_QUEUE_HPP_
#define CAPACITY_QUEUE_HPP_

#include <deque>

template <typename T>
class CapacityQueue 
{
public:
	CapacityQueue(uint32_t max_size)
		:max_size_(max_size) 
	{
	}

	uint32_t size(void) 
	{
		return clients_.size();
	}

	void push_back(T &entry) 
	{
		clients_.push_back(entry);
		if (max_size_ && clients_.size() > max_size_)
		{
			clients_.pop_front();
		}
	}

	T &front(void) 
	{
		return clients_.front();
	}

	void pop_front(void) 
	{
		clients_.pop_front();
	}
	
private:
	uint32_t max_size_;
	std::deque<T> clients_;
};

#endif

