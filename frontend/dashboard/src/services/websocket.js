import { useState, useEffect, useRef } from 'react';

export const useWebSocket = (url) => {
  const [ws, setWs] = useState(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimeout = useRef(null);

  useEffect(() => {
    const connect = () => {
      try {
        const socket = new WebSocket(url);

        socket.onopen = () => {
          console.log('WebSocket connected');
          setConnected(true);
          setWs(socket);
        };

        socket.onclose = () => {
          console.log('WebSocket disconnected');
          setConnected(false);
          setWs(null);
          
          reconnectTimeout.current = setTimeout(() => {
            console.log('Attempting to reconnect...');
            connect();
          }, 3000);
        };

        socket.onerror = (error) => {
          console.error('WebSocket error:', error);
        };
      } catch (error) {
        console.error('Failed to create WebSocket:', error);
      }
    };

    connect();

    return () => {
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
      if (ws) {
        ws.close();
      }
    };
  }, [url]);

  return ws;
};

export default useWebSocket;
