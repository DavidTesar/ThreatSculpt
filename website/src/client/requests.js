const requests = {
    post: async (url, data) => {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data),
        });
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      } catch (error) {
        throw new Error('Error performing request:', error);
      }
    },
    // You can define more functions like get, put, delete, etc.
  };
  
  export default requests;