#include <stdio.h>

#define MAX 20

void enqueue(int queue[], int *rear, int value) {
    queue[++(*rear)] = value;
}

int dequeue(int queue[], int *front) {
    return queue[++(*front)];
}

void BFS(int graph[MAX][MAX], int n, int start) {
    int visited[MAX] = {0};
    int queue[MAX], front = -1, rear = -1;

    visited[start] = 1;
    enqueue(queue, &rear, start);

    printf("BFS Traversal: ");

    while (front != rear) {
        int node = dequeue(queue, &front);
        printf("%d ", node);

        for (int i = 0; i < n; i++) {
            if (graph[node][i] && !visited[i]) {
                visited[i] = 1;
                enqueue(queue, &rear, i);
            }
        }
    }
    printf("\n");
}

int main() {
    int n = 5;
    int graph[MAX][MAX] = {
        {0,1,1,0,0},
        {1,0,1,1,0},
        {1,1,0,0,1},
        {0,1,0,0,1},
        {0,0,1,1,0}
    };

    BFS(graph, n, 0);

    return 0;
}
