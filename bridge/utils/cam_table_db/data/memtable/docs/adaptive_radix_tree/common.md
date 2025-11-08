```mermaid
flowchart TD
    Root[Root Node] --> A
    Root --> N
    Root --> R
    
    A --> A_Leaf1[Leaf]
    
    N --> D
    
    D --> D1[digit 1]
    D --> D2[digit 2]
    D --> D3[digit 3]
    
    D1 --> D1_Leaf[Leaf]
    D2 --> D2_Leaf[Leaf]
    D3 --> D3_Leaf[Leaf]
    
    R --> E
    R --> TYT
    
    E --> E_Leaf[Leaf]
    TYT --> TYT_Leaf[Leaf]
    
    %% Styling
    classDef default fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef leaf fill:#c8e6c9,stroke:#1b5e20,stroke-width:2px
    class A_Leaf1,D1_Leaf,D2_Leaf,D3_Leaf,E_Leaf,TYT_Leaf leaf
```

### This diagram shows:
- **Root node** with three children: A, N, R
- **Node N** has one child D
- **Node D** has three children (digit 1, digit 2, digit 3) leading to leaf nodes
- **Node R** has two children: E and TYT
- All paths eventually lead to **leaf nodes** (green)

The structure demonstrates how ART uses **adaptively sized nodes** - some nodes have many children (like D), while others have few children, showing the space-efficient adaptive nature of the data structure.

>  If each node of a tree has a positive budget, then that tree uses less than x bytes per key.
>

The Node Budget is:

A virtual "cost" that shows how much memory a node "consumes" or "saves" in relation to its children.
> The budget proves that ART will always find a sufficiently "economical" node configuration to fit into 52 bytes per key in the worst case!