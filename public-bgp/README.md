# Deprecated in v2

Starting with **AutoBgpFeed v2**, dynamic BGP peering (`neighbor range 0.0.0.0/0 external`) is handled directly by **BIRD 2** inside `bgp-core`.
The separate `public-bgp` (FRRouting) container is no longer used or needed.
