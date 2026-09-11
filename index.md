---
layout: default
title: Home
---

# Hello, World!

Welcome to my personal blog.

## Posts

<ul>
{% for post in site.posts %}
  <li>
    <span>{{ post.date | date: "%-d %B %Y" }}</span> &mdash;
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
  </li>
{% else %}
  <li>No posts yet.</li>
{% endfor %}
</ul>
