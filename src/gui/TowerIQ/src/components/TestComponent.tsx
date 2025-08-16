import { useState } from 'react';

interface TestComponentProps {
  title?: string;
}

export function TestComponent({ title = "Hot Reload Test" }: TestComponentProps) {
  const [count, setCount] = useState(0);
  const [message, setMessage] = useState("🔥 Hot reloading is working! Edit this text to see instant updates!");

  return (
    <div style={{
      padding: '20px',
      border: '2px solid #646cff',
      borderRadius: '8px',
      margin: '20px 0',
      backgroundColor: '#2f2f2f'
    }}>
      <h2>{title}</h2>
      <p>{message}</p>
      
      <div style={{ marginBottom: '15px' }}>
        <button 
          onClick={() => setCount(count + 1)}
          style={{
            padding: '8px 16px',
            backgroundColor: '#646cff',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            marginRight: '10px'
          }}
        >
          Count: {count}
        </button>
        
        <button 
          onClick={() => setCount(0)}
          style={{
            padding: '8px 16px',
            backgroundColor: '#ff6464',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Reset
        </button>
      </div>
      
      <div style={{ fontSize: '14px', color: '#666' }}>
        <p>🔄 Try editing this component and save - you should see changes instantly!</p>
        <p>⏰ Last updated: {new Date().toLocaleTimeString()}</p>
      </div>
    </div>
  );
}
