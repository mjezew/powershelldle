// JS Hook for storing some state in localStorage in the browser.
// The server requests stored data and clears it when requested.
export const LocalStorage = {
  mounted() {
    this.handleEvent("store", (obj) => this.store(obj));
    this.handleEvent("clear", (obj) => this.clear(obj));
    this.handleEvent("restore", (obj) => this.restore(obj));
  },

  store(obj) {
    localStorage.setItem(obj.key, obj.data);
  },

  restore(obj) {
    const data = localStorage.getItem(obj.key);
    this.pushEvent(obj.event, data);
  },

  clear(obj) {
    localStorage.removeItem(obj.key);
  },
};
